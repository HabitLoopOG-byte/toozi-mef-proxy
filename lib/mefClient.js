const crypto = require('crypto');
const fetch = require('node-fetch');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { buildLoginEnvelope, buildSendSubmissionsEnvelope } = require('./envelopes');
const { setSamlAssertion, getSamlAssertion } = require('./session');

// ATS endpoints only — NEVER production. These are hardcoded on purpose.
const ATS_BASE = 'https://la.alt.www4.irs.gov/a2a/mef';
const ENDPOINTS = {
  login: `${ATS_BASE}/Login`,
  sendSubmissions: `${ATS_BASE}/mime/SendSubmissions`,
};

const SAML_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';

function getMefCredentials() {
  // Cert + key are stored as base64-encoded PEM because Railway's env var UI
  // strips newlines from multi-line values, which corrupts PEM formatting.
  const certB64 = process.env.IDENTRUST_CERT_B64;
  const keyB64 = process.env.IDENTRUST_KEY_B64;
  const etin = process.env.IRS_ETIN;
  const appSysId = process.env.IRS_APPSYSID;

  const missing = [];
  if (!certB64) missing.push('IDENTRUST_CERT_B64');
  if (!keyB64) missing.push('IDENTRUST_KEY_B64');
  if (!etin) missing.push('IRS_ETIN');
  if (!appSysId) missing.push('IRS_APPSYSID');
  if (missing.length) {
    throw new Error(`Missing MeF credentials: ${missing.join(', ')}`);
  }

  const rawCertPem = Buffer.from(certB64, 'base64').toString('utf8');
  const rawKeyPem = Buffer.from(keyB64, 'base64').toString('utf8');

  // The decoded PEM may include pkcs12-dump preamble (Bag Attributes,
  // subject=, issuer=) before the actual -----BEGIN CERTIFICATE----- line.
  // Node's X509/verify APIs tolerate this for the key but NOT for the cert
  // header embedded in the BinarySecurityToken — IRS rejects anything that
  // isn't a pure base64 DER blob. Extract just the first cert / key block.
  const certMatch = rawCertPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  if (!certMatch) {
    throw new Error('IDENTRUST_CERT_B64 does not contain a PEM CERTIFICATE block');
  }
  const cert = certMatch[0];

  const keyMatch = rawKeyPem.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/);
  if (!keyMatch) {
    throw new Error('IDENTRUST_KEY_B64 does not contain a PEM PRIVATE KEY block');
  }
  const privateKey = keyMatch[0];

  return { cert, privateKey, etin, appSysId };
}

function extractSamlAssertion(responseXml) {
  const doc = new DOMParser({ errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} } })
    .parseFromString(responseXml, 'text/xml');
  const assertions = doc.getElementsByTagNameNS(SAML_NS, 'Assertion');
  if (!assertions || assertions.length === 0) return null;
  const assertion = assertions[0];
  const conditions = assertion.getElementsByTagNameNS(SAML_NS, 'Conditions')[0];
  const notOnOrAfter = conditions ? conditions.getAttribute('NotOnOrAfter') : null;
  const xml = new XMLSerializer().serializeToString(assertion);
  return { xml, notOnOrAfter };
}

function logSoap(label, payload) {
  const banner = `===== ${label} =====`;
  console.log(`[mef-proxy] ${banner}`);
  console.log(payload);
  console.log(`[mef-proxy] ${'='.repeat(banner.length)}`);
}

async function postSoap(url, envelopeXml, soapAction = '') {
  const startedAt = Date.now();
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      'SOAPAction': soapAction,
      'User-Agent': 'Toozi-MeF-Client/1.1',
    },
    body: envelopeXml,
  });
  const body = await res.text();
  const headers = {};
  res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
  return {
    status: res.status,
    statusText: res.statusText,
    headers,
    body,
    durationMs: Date.now() - startedAt,
  };
}

async function loginMeF() {
  const { cert, privateKey, etin, appSysId } = getMefCredentials();

  const { xml: envelope, messageId, ids } = buildLoginEnvelope({
    etin,
    appSysId,
    clientSoftwareTxt: 'Toozi',
    cert,
    privateKey,
  });

  logSoap(`LOGIN REQUEST (messageId=${messageId})`, envelope);

  const response = await postSoap(ENDPOINTS.login, envelope, 'Login');

  logSoap(
    `LOGIN RESPONSE status=${response.status} (${response.durationMs}ms)`,
    response.body
  );

  let samlAssertion = null;
  if (response.status === 200) {
    samlAssertion = extractSamlAssertion(response.body);
    if (samlAssertion) {
      setSamlAssertion({
        samlAssertionXml: samlAssertion.xml,
        notOnOrAfter: samlAssertion.notOnOrAfter,
        rawLoginResponse: response.body,
      });
      console.log(
        `[mef-proxy] SAML cached. notOnOrAfter=${samlAssertion.notOnOrAfter}`
      );
    } else {
      console.warn('[mef-proxy] Login 200 but no SAML Assertion found in response');
    }
  }

  return {
    success: response.status === 200 && !!samlAssertion,
    messageId,
    ids,
    request: envelope,
    response,
    samlAssertion,
  };
}

async function ensureSamlAssertion() {
  const cached = getSamlAssertion();
  if (cached) return cached;
  const login = await loginMeF();
  if (!login.success) {
    throw new Error(`MeF login failed: HTTP ${login.response.status}`);
  }
  return getSamlAssertion();
}

/**
 * SendSubmissions via multipart/related MIME (RFC 2387 / SOAP with Attachments).
 *
 * IRS /mime/SendSubmissions expects a two-part message:
 *   Part 1: text/xml — the SOAP envelope (UsernameToken + cached SAML assertion)
 *   Part 2: application/octet-stream — the submission ZIP
 *
 * The SAML was issued by IRS on Login so we do NOT sign this envelope ourselves.
 */
async function sendSubmissions({ submissionId, electronicPostmarkTs, zipBuffer }) {
  if (!submissionId || !electronicPostmarkTs) {
    throw new Error('sendSubmissions: submissionId and electronicPostmarkTs required');
  }
  if (!Buffer.isBuffer(zipBuffer) || zipBuffer.length === 0) {
    throw new Error('sendSubmissions: zipBuffer must be a non-empty Buffer');
  }

  const { etin, appSysId } = getMefCredentials();
  const saml = await ensureSamlAssertion();

  const { xml: envelope, messageId } = buildSendSubmissionsEnvelope({
    etin,
    appSysId,
    clientSoftwareTxt: 'Toozi',
    samlAssertionXml: saml.samlAssertionXml,
    submissions: [{ submissionId, electronicPostmarkTs }],
  });

  // Build the multipart/related body. Boundary must not appear in either part.
  const boundary = `MIMEBoundary_${crypto.randomBytes(16).toString('hex')}`;
  const rootCid = `root-${messageId}@toozi`;
  const attCid = `attachment-${submissionId}@toozi`;
  const CRLF = '\r\n';

  const part1Headers =
    `--${boundary}${CRLF}` +
    `Content-Type: text/xml; charset=utf-8${CRLF}` +
    `Content-Transfer-Encoding: 8bit${CRLF}` +
    `Content-ID: <${rootCid}>${CRLF}` +
    CRLF;

  const part2Headers =
    `${CRLF}--${boundary}${CRLF}` +
    `Content-Type: application/octet-stream${CRLF}` +
    `Content-Transfer-Encoding: binary${CRLF}` +
    `Content-ID: <${attCid}>${CRLF}` +
    CRLF;

  const closingBoundary = `${CRLF}--${boundary}--${CRLF}`;

  const mimeBody = Buffer.concat([
    Buffer.from(part1Headers, 'utf8'),
    Buffer.from(envelope, 'utf8'),
    Buffer.from(part2Headers, 'utf8'),
    zipBuffer,
    Buffer.from(closingBoundary, 'utf8'),
  ]);

  const contentType = `multipart/related; type="text/xml"; start="<${rootCid}>"; boundary="${boundary}"`;

  logSoap(`SEND_SUBMISSIONS REQUEST (messageId=${messageId}, submissionId=${submissionId})`, envelope);
  console.log(
    `[mef-proxy] MIME boundary=${boundary} | zip=${zipBuffer.length}B | total=${mimeBody.length}B | contentType=${contentType}`
  );

  const startedAt = Date.now();
  const res = await fetch(ENDPOINTS.sendSubmissions, {
    method: 'POST',
    headers: {
      'Content-Type': contentType,
      'SOAPAction': 'SendSubmissions',
      'User-Agent': 'Toozi-MeF-Client/1.1',
    },
    body: mimeBody,
  });
  const responseBody = await res.text();
  const durationMs = Date.now() - startedAt;
  const responseHeaders = {};
  res.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });

  logSoap(`SEND_SUBMISSIONS RESPONSE status=${res.status} (${durationMs}ms)`, responseBody);

  return {
    success: res.status === 200,
    messageId,
    submissionId,
    request: envelope,
    mimeBoundary: boundary,
    mimeTotalBytes: mimeBody.length,
    response: {
      status: res.status,
      statusText: res.statusText,
      headers: responseHeaders,
      body: responseBody,
      durationMs,
    },
  };
}

module.exports = {
  loginMeF,
  sendSubmissions,
  ensureSamlAssertion,
  ENDPOINTS,
};
