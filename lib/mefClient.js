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
  const cert = process.env.IDENTRUST_CERT;
  const privateKey = process.env.IDENTRUST_PRIVATE_KEY;
  const etin = process.env.IRS_ETIN;
  const appSysId = process.env.IRS_APPSYSID;

  const missing = [];
  if (!cert) missing.push('IDENTRUST_CERT');
  if (!privateKey) missing.push('IDENTRUST_PRIVATE_KEY');
  if (!etin) missing.push('IRS_ETIN');
  if (!appSysId) missing.push('IRS_APPSYSID');
  if (missing.length) {
    throw new Error(`Missing MeF credentials: ${missing.join(', ')}`);
  }

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

async function sendSubmissions({ submissions }) {
  if (!Array.isArray(submissions) || submissions.length === 0) {
    throw new Error('sendSubmissions: submissions array required');
  }

  const { etin, appSysId } = getMefCredentials();
  const saml = await ensureSamlAssertion();

  const { xml: envelope, messageId } = buildSendSubmissionsEnvelope({
    etin,
    appSysId,
    clientSoftwareTxt: 'Toozi',
    samlAssertionXml: saml.samlAssertionXml,
    submissions,
  });

  logSoap(`SEND_SUBMISSIONS REQUEST (messageId=${messageId})`, envelope);

  const response = await postSoap(ENDPOINTS.sendSubmissions, envelope, 'SendSubmissions');

  logSoap(
    `SEND_SUBMISSIONS RESPONSE status=${response.status} (${response.durationMs}ms)`,
    response.body
  );

  return {
    success: response.status === 200,
    messageId,
    request: envelope,
    response,
  };
}

module.exports = {
  loginMeF,
  sendSubmissions,
  ensureSamlAssertion,
  ENDPOINTS,
};
