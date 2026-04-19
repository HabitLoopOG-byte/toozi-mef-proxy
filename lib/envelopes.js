const { SignedXml } = require('xml-crypto');
const { generateXmlId, generateMessageId } = require('./ids');

const NS = {
  soap: 'http://schemas.xmlsoap.org/soap/envelope/',
  wsu: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
  wsse: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
  mefhdr: 'http://www.irs.gov/a2a/mef/MeFHeader.xsd',
  mefmsi: 'http://www.irs.gov/a2a/mef/MeFMSIServices.xsd',
  meftrans: 'http://www.irs.gov/a2a/mef/MeFTransmitterService.xsd',
  xsd: 'http://www.w3.org/2001/XMLSchema',
  xsi: 'http://www.w3.org/2001/XMLSchema-instance',
};

const C14N_INCL_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
const C14N_EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
const X509_VALUE_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
const B64_ENCODING = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

function extractBase64Cert(pem) {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

function buildMeFHeaderXml({ action, messageId, messageTs, etin, appSysId, clientSoftwareTxt, wsuId }) {
  return (
    `<MeFHeader xmlns="${NS.mefhdr}" xmlns:xsd="${NS.xsd}" xmlns:xsi="${NS.xsi}" Id="MefHeader" u:Id="${wsuId}">` +
    `<MessageID>${messageId}</MessageID>` +
    `<Action>${action}</Action>` +
    `<MessageTs>${messageTs}</MessageTs>` +
    `<ETIN>${etin}</ETIN>` +
    `<SessionKeyCd>Y</SessionKeyCd>` +
    `<TestCd>P</TestCd>` +
    `<AppSysID>${appSysId}</AppSysID>` +
    `<WSDLVersionNum>10.9</WSDLVersionNum>` +
    `<ClientSoftwareTxt>${clientSoftwareTxt}</ClientSoftwareTxt>` +
    `</MeFHeader>`
  );
}

/**
 * Build + sign the Login SOAP envelope (matches LoginSamp-LR.txt).
 * Signs three references: MeFHeader, Body, Timestamp — RSA-SHA256 + exc-c14n.
 */
function buildLoginEnvelope({ etin, appSysId, clientSoftwareTxt = 'Toozi', cert, privateKey }) {
  if (!etin || !appSysId || !cert || !privateKey) {
    throw new Error('buildLoginEnvelope: etin, appSysId, cert, privateKey all required');
  }

  const now = new Date();
  const messageTs = now.toISOString();
  const created = messageTs;
  const expires = new Date(now.getTime() + 20 * 60 * 1000).toISOString();

  const messageId = generateMessageId(etin);
  const mefHeaderId = generateXmlId('MeFHeader');
  const bodyId = generateXmlId('Body');
  const timestampId = generateXmlId('Timestamp');
  const x509Id = generateXmlId('X509');
  const sigId = generateXmlId('SIG');
  const strId = generateXmlId('STR');

  const certB64 = extractBase64Cert(cert);

  const mefHeaderXml = buildMeFHeaderXml({
    action: 'Login',
    messageId,
    messageTs,
    etin,
    appSysId,
    clientSoftwareTxt,
    wsuId: mefHeaderId,
  });

  // Unsigned template. Signature will be inserted after BinarySecurityToken by xml-crypto.
  const template =
    `<Envelope xmlns="${NS.soap}" xmlns:u="${NS.wsu}">` +
    `<Header>` +
    mefHeaderXml +
    `<ns3:Security xmlns:ns3="${NS.wsse}">` +
    `<wsse:BinarySecurityToken EncodingType="${B64_ENCODING}" ValueType="${X509_VALUE_TYPE}" xmlns:wsu="${NS.wsu}" wsu:Id="${x509Id}" xmlns:wsse="${NS.wsse}">${certB64}</wsse:BinarySecurityToken>` +
    `<u:Timestamp u:Id="${timestampId}"><u:Created>${created}</u:Created><u:Expires>${expires}</u:Expires></u:Timestamp>` +
    `</ns3:Security>` +
    `</Header>` +
    `<Body xmlns:xsd="${NS.xsd}" xmlns:xsi="${NS.xsi}" u:Id="${bodyId}">` +
    `<LoginRequest xmlns="${NS.mefmsi}"/>` +
    `</Body>` +
    `</Envelope>`;

  const sig = new SignedXml({
    privateKey,
    publicCert: cert,
    canonicalizationAlgorithm: C14N_INCL_WITH_COMMENTS,
    signatureAlgorithm: SIG_RSA_SHA256,
  });

  // KeyInfo points to the inline BinarySecurityToken via wsse:SecurityTokenReference
  sig.getKeyInfoContent = () =>
    `<wsse:SecurityTokenReference xmlns:wsu="${NS.wsu}" wsu:Id="${strId}" xmlns:wsse="${NS.wsse}">` +
    `<wsse:Reference URI="#${x509Id}" ValueType="${X509_VALUE_TYPE}"/>` +
    `</wsse:SecurityTokenReference>`;

  const addRef = (xpathLocalName, uri, prefixList) =>
    sig.addReference({
      xpath: `//*[local-name(.)='${xpathLocalName}']`,
      uri: `#${uri}`,
      digestAlgorithm: DIGEST_SHA256,
      transforms: [C14N_EXC],
      inclusiveNamespacesPrefixList: prefixList,
    });

  addRef('MeFHeader', mefHeaderId, '#default u');
  addRef('Body', bodyId, '#default u');
  addRef('Timestamp', timestampId, 'ns3 #default u');

  sig.computeSignature(template, {
    prefix: '',
    attrs: { Id: sigId },
    location: {
      reference: `//*[local-name(.)='BinarySecurityToken']`,
      action: 'after',
    },
  });

  return {
    xml: sig.getSignedXml(),
    messageId,
    ids: { mefHeaderId, bodyId, timestampId, x509Id, sigId, strId },
  };
}

/**
 * Build the SendSubmissions SOAP envelope (matches SendSamp-LR.txt).
 * No signing by us — the SAML assertion is IRS-issued and already self-signed.
 *
 * @param submissions [{ submissionId, electronicPostmarkTs }]
 * @param samlAssertionXml — the raw <saml:Assertion>...</saml:Assertion> string from the Login response
 */
function buildSendSubmissionsEnvelope({
  etin,
  appSysId,
  clientSoftwareTxt = 'Toozi',
  samlAssertionXml,
  submissions,
}) {
  if (!etin || !appSysId || !samlAssertionXml || !Array.isArray(submissions) || submissions.length === 0) {
    throw new Error('buildSendSubmissionsEnvelope: etin, appSysId, samlAssertionXml, non-empty submissions required');
  }

  const messageTs = new Date().toISOString();
  const messageId = generateMessageId(etin);
  const mefHeaderId = generateXmlId('MeFHeader');

  const mefHeaderXml = buildMeFHeaderXml({
    action: 'SendSubmissions',
    messageId,
    messageTs,
    etin,
    appSysId,
    clientSoftwareTxt,
    wsuId: mefHeaderId,
  });

  const submissionDataXml = submissions
    .map(
      (s) =>
        `<SubmissionData><SubmissionId>${s.submissionId}</SubmissionId><ElectronicPostmarkTs>${s.electronicPostmarkTs}</ElectronicPostmarkTs></SubmissionData>`
    )
    .join('');

  const envelope =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<Envelope xmlns="${NS.soap}" xmlns:u="${NS.wsu}">` +
    `<Header>` +
    mefHeaderXml +
    `<wsse:Security xmlns:wsse="${NS.wsse}">` +
    `<wsse:UsernameToken xmlns:wsu="${NS.wsu}">` +
    `<wsse:Username>${appSysId}</wsse:Username>` +
    `</wsse:UsernameToken>` +
    samlAssertionXml +
    `</wsse:Security>` +
    `</Header>` +
    `<Body xmlns:xsd="${NS.xsd}" xmlns:xsi="${NS.xsi}">` +
    `<SendSubmissionsRequest xmlns="${NS.meftrans}">` +
    `<SubmissionDataList>${submissionDataXml}</SubmissionDataList>` +
    `</SendSubmissionsRequest>` +
    `</Body>` +
    `</Envelope>`;

  return { xml: envelope, messageId };
}

module.exports = {
  buildLoginEnvelope,
  buildSendSubmissionsEnvelope,
  extractBase64Cert,
  NS,
};
