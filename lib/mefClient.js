const crypto = require('crypto');
const fetch = require('node-fetch');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const {
  buildLoginEnvelope,
  buildSendSubmissionsEnvelope,
  buildGetAcknowledgementsEnvelope,
  buildSignedGetAcknowledgementsEnvelope,
} = require('./envelopes');
const { setSamlAssertion, getSamlAssertion } = require('./session');

// ATS endpoints only — NEVER production. These are hardcoded on purpose.
// Environment selector is paired with the TestCd hardcoded in envelopes.js:
//   ATS  host = la.alt.www4.irs.gov ↔ TestCd=T
//   PROD host = la.www4.irs.gov     ↔ TestCd=P
// Flipping the URL without flipping TestCd (or vice versa) causes IRS to
// reject SendSubmissions as REQSTI004000006 "Invalid ETIN for this login
// name". Both values must move together.
const ATS_HOST = 'la.alt.www4.irs.gov';
const ATS_BASE = `https://${ATS_HOST}/a2a/mef`;

// GetAcknowledgements endpoint candidates. First live ATS call with the
// `/a2a/mef/GetAcknowledgements` path returned a Lorem Ipsum HTML catch-all
// page (11375 bytes, same across all SOAP body variants) — meaning IRS's
// front-door router rejected the URL before the request ever reached the
// MeF processing engine. IRS's A2A MSI services are typically under a
// `MSIServices` subpath, unlike SendSubmissions which uses `/mime/` because
// of its multipart body. We expose multiple candidates so the operator can
// A/B them without redeploying.
// Pub 5830 §4.3.7 says GetAcknowledgements lives on the same base URL as
// Login + SendSubmissions. The direct `/a2a/mef/GetAcknowledgements` path
// got a Lorem Ipsum HTML catch-all page on first live test — but we now
// know that was likely because the envelope was unsigned (SAML-only
// pattern, not the X.509-signed pattern GetAcks requires as a Transmitter
// Service call). Making `direct` the default again now that we also send
// a signed envelope by default.
const GET_ACKS_ENDPOINT_VARIANTS = {
  'direct':            `${ATS_BASE}/GetAcknowledgements`,                 // Pub 5830 §4.3.7 path
  'msi_services':      `${ATS_BASE}/MSIServices/GetAcknowledgements`,     // alt — IRS MSI services subpath
  'msi_lowercase':     `${ATS_BASE}/msiservices/GetAcknowledgements`,     // case-variant fallback
  'msi_services_root': `${ATS_BASE}/MSIServices`,                         // unified dispatcher — SOAPAction routes
  'get_acks':          `${ATS_BASE}/GetAcks`,                             // long shot — abbreviated name
  'transmitter':       `${ATS_BASE}/Transmitter/GetAcknowledgements`,     // alt — Transmitter subpath
};

const ENDPOINTS = {
  login: `${ATS_BASE}/Login`,
  sendSubmissions: `${ATS_BASE}/mime/SendSubmissions`,
  getAcknowledgementsDefault: GET_ACKS_ENDPOINT_VARIANTS.direct,
};

// Sanity check at module load — loud failure if someone edits one without the
// other.
const hostsToCheck = [
  ENDPOINTS.login,
  ENDPOINTS.sendSubmissions,
  ENDPOINTS.getAcknowledgementsDefault,
  ...Object.values(GET_ACKS_ENDPOINT_VARIANTS),
];
for (const u of hostsToCheck) {
  if (new URL(u).host !== ATS_HOST) {
    throw new Error(`mefClient endpoint drift: ${u} does not match expected host ${ATS_HOST}`);
  }
}

const SAML_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';

function getMefCredentials() {
  // Three distinct IRS identifiers. Do NOT confuse:
  //   IRS_ETIN     — 5 digits. Electronic Transmitter ID. MeFHeader <ETIN>.
  //   IRS_APPSYSID — variable length. Application System ID. MeFHeader
  //                  <AppSysID> and SendSubmissions UsernameToken.
  //   IRS_EFIN     — 6 digits. Electronic Filing ID for the ERO. Used by
  //                  ats-test-runner / submit-mef-return for SubmissionId
  //                  generation; NOT read here.
  //
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

  // Format validation — catches the classic mistake of pasting AppSysID into
  // IRS_ETIN or vice versa. IRS rejects mismatches with REQSTI004000006
  // ("Invalid ETIN for this login name").
  if (!/^\d{5}$/.test(etin)) {
    throw new Error(
      `IRS_ETIN must be exactly 5 digits (got "${etin}", length=${etin.length}). ` +
      `ETIN is NOT the same as EFIN (6 digits) or AppSysID. Check IRS e-Services.`
    );
  }
  if (!/^\d+$/.test(appSysId)) {
    throw new Error(
      `IRS_APPSYSID must be digits only (got "${appSysId}"). ` +
      `This is the Application System ID assigned when you registered your A2A application.`
    );
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
  const assertionId = assertion.getAttribute('AssertionID');
  const issueInstant = assertion.getAttribute('IssueInstant');
  const xml = new XMLSerializer().serializeToString(assertion);
  return { xml, notOnOrAfter, assertionId, issueInstant };
}

// Pull the AssertionID out of a cached SAML assertion XML string so we can log
// which one is being used on every SendSubmissions call (proves freshness).
function getAssertionIdFromXml(samlAssertionXml) {
  const match = samlAssertionXml && samlAssertionXml.match(/AssertionID="([^"]+)"/);
  return match ? match[1] : '(no AssertionID found)';
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

  console.log(`[mef-proxy] LOGIN_URL=${ENDPOINTS.login}`);
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
        `[mef-proxy] SAML cached. AssertionID=${samlAssertion.assertionId} IssueInstant=${samlAssertion.issueInstant} notOnOrAfter=${samlAssertion.notOnOrAfter}`
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

  // Force the session check to run RIGHT NOW, not rely on a stale reference.
  // ensureSamlAssertion() either returns the existing cache (if valid) or
  // performs a fresh Login before returning.
  const before = Date.now();
  const saml = await ensureSamlAssertion();
  const ensureDurationMs = Date.now() - before;
  const assertionIdInUse = getAssertionIdFromXml(saml.samlAssertionXml);
  const ageMs = Date.now() - (saml.storedAt ? saml.storedAt.getTime() : Date.now());
  const expiresInMs = saml.notOnOrAfter ? saml.notOnOrAfter.getTime() - Date.now() : null;
  console.log(
    `[mef-proxy] SEND_SUBMISSIONS using SAML: AssertionID=${assertionIdInUse} ` +
    `age=${Math.round(ageMs / 1000)}s ` +
    `expiresIn=${expiresInMs == null ? 'unknown' : Math.round(expiresInMs / 1000) + 's'} ` +
    `(ensureSamlAssertion took ${ensureDurationMs}ms — >500ms usually indicates a fresh Login round-trip)`
  );

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

  console.log(`[mef-proxy] SEND_SUBMISSIONS_URL=${ENDPOINTS.sendSubmissions}`);
  console.log(`[mef-proxy] LOGIN_URL=${ENDPOINTS.login}`);
  const loginHost = new URL(ENDPOINTS.login).host;
  const sendHost = new URL(ENDPOINTS.sendSubmissions).host;
  console.log(
    `[mef-proxy] HOST_CHECK: login=${loginHost} sendSubmissions=${sendHost} same_host=${loginHost === sendHost}`
  );
  if (loginHost !== sendHost) {
    // Belt-and-suspenders: IRS rejects cross-host SAML reuse as REQSTI004000006.
    throw new Error(`Login host (${loginHost}) and SendSubmissions host (${sendHost}) must match`);
  }
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

/**
 * GetAcknowledgements — poll IRS for the accept/reject verdict of previously
 * sent submissions. Not a MIME multipart request; just plain SOAP.
 *
 * Reuses the cached SAML assertion from Login (same as SendSubmissions).
 * IRS allows up to a few hundred SubmissionIds per request — for our use
 * case (checking 1–10 ATS scenarios at a time) a single batch is fine.
 *
 * Returns the raw SOAP response body. The caller (edge function) is
 * responsible for parsing the response XML into per-submission acks.
 */
async function getAcknowledgements({
  submissionIds,
  schemaVariant,
  endpointVariant,
  soapActionVariant,
  envelopeMode,
}) {
  if (!Array.isArray(submissionIds) || submissionIds.length === 0) {
    throw new Error('getAcknowledgements: non-empty submissionIds required');
  }

  const { cert, privateKey, etin, appSysId } = getMefCredentials();

  // Envelope signing mode:
  //   'signed' (default, Pub 5830 §4.3.7) — X.509-signed with IdenTrust cert,
  //                                          mirrors Login's WS-Security pattern
  //   'saml'                              — SAML-only, same pattern as SendSubmissions.
  //                                          Kept for regression A/B testing only.
  const mode = envelopeMode || 'signed';
  if (!['signed', 'saml'].includes(mode)) {
    throw new Error(`Unknown envelopeMode "${mode}". Known: signed, saml`);
  }

  // Resolve endpoint URL — named variant table lookup.
  const endpointKey = endpointVariant || 'direct';
  const endpointUrl = GET_ACKS_ENDPOINT_VARIANTS[endpointKey];
  if (!endpointUrl) {
    throw new Error(
      `Unknown endpointVariant "${endpointKey}". Known: ${Object.keys(GET_ACKS_ENDPOINT_VARIANTS).join(', ')}`
    );
  }

  // SOAPAction header format variants.
  const soapActionsByKey = {
    'bare':       'GetAcknowledgements',
    'quoted':     '"GetAcknowledgements"',
    'urn':        'http://www.irs.gov/a2a/mef/GetAcknowledgements',
    'quoted_urn': '"http://www.irs.gov/a2a/mef/GetAcknowledgements"',
  };
  const soapActionKey = soapActionVariant || 'bare';
  const soapAction = soapActionsByKey[soapActionKey];
  if (soapAction === undefined) {
    throw new Error(
      `Unknown soapActionVariant "${soapActionKey}". Known: ${Object.keys(soapActionsByKey).join(', ')}`
    );
  }

  let envelope;
  let messageId;

  if (mode === 'signed') {
    // Pub 5830 §4.3.7 path — X.509-signed envelope with the IdenTrust cert.
    console.log(
      `[mef-proxy] GET_ACKS mode=signed (X.509) ` +
      `submissionIds=${submissionIds.length} schema=${schemaVariant || 'default'} ` +
      `endpoint=${endpointKey} soapAction=${soapActionKey}`
    );
    ({ xml: envelope, messageId } = buildSignedGetAcknowledgementsEnvelope({
      etin,
      appSysId,
      clientSoftwareTxt: 'Toozi',
      cert,
      privateKey,
      submissionIds,
      schemaVariant,
    }));
  } else {
    // 'saml' mode — cached SAML assertion from Login, no XMLDSig signature.
    const before = Date.now();
    const saml = await ensureSamlAssertion();
    const ensureDurationMs = Date.now() - before;
    const assertionIdInUse = getAssertionIdFromXml(saml.samlAssertionXml);
    console.log(
      `[mef-proxy] GET_ACKS mode=saml AssertionID=${assertionIdInUse} ` +
      `(ensureSamlAssertion took ${ensureDurationMs}ms) ` +
      `submissionIds=${submissionIds.length} schema=${schemaVariant || 'default'} ` +
      `endpoint=${endpointKey} soapAction=${soapActionKey}`
    );
    ({ xml: envelope, messageId } = buildGetAcknowledgementsEnvelope({
      etin,
      appSysId,
      clientSoftwareTxt: 'Toozi',
      samlAssertionXml: saml.samlAssertionXml,
      submissionIds,
      schemaVariant,
    }));
  }

  console.log(`[mef-proxy] GET_ACKS_URL=${endpointUrl}  (endpointVariant=${endpointKey})`);
  console.log(`[mef-proxy] GET_ACKS_SOAPACTION=${soapAction}  (soapActionVariant=${soapActionKey})`);
  logSoap(
    `GET_ACKS REQUEST (messageId=${messageId}, submissionIds=${submissionIds.length}, mode=${mode}, schema=${schemaVariant || 'default'})`,
    envelope
  );

  const response = await postSoap(endpointUrl, envelope, soapAction);

  logSoap(
    `GET_ACKS RESPONSE status=${response.status} ${response.statusText || ''} (${response.durationMs}ms) bodyBytes=${response.body.length}`,
    response.body
  );

  return {
    success: response.status === 200,
    messageId,
    submissionIds,
    envelopeMode: mode,
    schemaVariant: schemaVariant || 'default',
    endpointVariant: endpointKey,
    endpointUrl,
    soapActionVariant: soapActionKey,
    soapAction,
    request: envelope,
    response,
  };
}

module.exports = {
  loginMeF,
  sendSubmissions,
  getAcknowledgements,
  ensureSamlAssertion,
  ENDPOINTS,
};
