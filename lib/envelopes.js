const crypto = require('crypto');
const { DOMParser } = require('@xmldom/xmldom');
const { ExclusiveCanonicalization, C14nCanonicalizationWithComments } = require('xml-crypto');
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
  dsig: 'http://www.w3.org/2000/09/xmldsig#',
  excc14n: 'http://www.w3.org/2001/10/xml-exc-c14n#',
};

const C14N_INCL_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
const C14N_EXC = NS.excc14n;
const SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
const X509_VALUE_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
const B64_ENCODING = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
const SIGNATURE_VALUE_PLACEHOLDER = '__TOOZI_SIG_VAL_PLACEHOLDER__';

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

function findFirstByLocalName(doc, localName) {
  const all = doc.getElementsByTagName('*');
  for (let i = 0; i < all.length; i++) {
    if (all[i].localName === localName) return all[i];
  }
  return null;
}

function excDigest(node, prefixList) {
  const canon = new ExclusiveCanonicalization().process(node, {
    inclusiveNamespacesPrefixList: prefixList,
  });
  return crypto.createHash('sha256').update(canon, 'utf8').digest('base64');
}

function buildReferenceXml(uri, prefixList, digestValue) {
  return (
    `<Reference URI="#${uri}">` +
    `<Transforms>` +
    `<Transform Algorithm="${C14N_EXC}">` +
    `<InclusiveNamespaces PrefixList="${prefixList}" xmlns="${NS.excc14n}"/>` +
    `</Transform>` +
    `</Transforms>` +
    `<DigestMethod Algorithm="${DIGEST_SHA256}"/>` +
    `<DigestValue>${digestValue}</DigestValue>` +
    `</Reference>`
  );
}

/**
 * Build + sign the Login SOAP envelope (matches LoginSamp-LR.txt).
 *
 * Signature is constructed manually rather than via xml-crypto's SignedXml
 * because that API (a) overrode our explicit Reference URIs with the plain
 * `Id="MefHeader"` attribute, and (b) omitted the <InclusiveNamespaces>
 * child of each <Transform>. Both are required by IRS — omitting them
 * yields wsse:FailedCheck.
 *
 * xml-crypto's ExclusiveCanonicalization and C14nCanonicalizationWithComments
 * classes are still used for the canonicalization primitives.
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
  const keyInfoId = generateXmlId('KIF');
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

  // Step 1 — build the envelope WITHOUT the Signature element so we can compute
  // digests over MeFHeader/Body/Timestamp in their natural document context.
  // (Their ancestor namespace scope is identical with or without Signature as a sibling.)
  const digestEnvelope =
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

  const digestDoc = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
  }).parseFromString(digestEnvelope);

  const mefHeaderEl = findFirstByLocalName(digestDoc, 'MeFHeader');
  const bodyEl = findFirstByLocalName(digestDoc, 'Body');
  const timestampEl = findFirstByLocalName(digestDoc, 'Timestamp');
  if (!mefHeaderEl || !bodyEl || !timestampEl) {
    throw new Error('buildLoginEnvelope: failed to locate signed elements in template');
  }

  const mefHeaderDigest = excDigest(mefHeaderEl, '#default u');
  const bodyDigest = excDigest(bodyEl, '#default u');

  // Manually construct the canonical Timestamp string, bypassing the DOM
  // canonicalizer entirely for this element. xml-crypto's exc-c14n won't
  // emit inclusive-namespace prefixes that aren't visibly utilized, and
  // setAttributeNS on @xmldom can't inject a default xmlns declaration.
  // Namespace declarations are sorted per exc-c14n spec: default xmlns
  // first, then prefixed declarations alphabetically. Double quotes
  // required by c14n.
  const TS_BUILD_TAG = 'manual-c14n-v3-all-three-xmlns';
  const timestampC14n =
    '<u:Timestamp' +
    ` xmlns="${NS.soap}"` +
    ` xmlns:ns3="${NS.wsse}"` +
    ` xmlns:u="${NS.wsu}"` +
    ` u:Id="${timestampId}">` +
    `<u:Created>${created}</u:Created>` +
    `<u:Expires>${expires}</u:Expires>` +
    '</u:Timestamp>';

  // Sanity assertion — if any of the three declarations is missing, bail loud
  // rather than silently shipping an envelope that will fail at IRS. This
  // also proves to the operator that the manual-c14n code path is actually
  // the one being executed.
  const required = [
    `xmlns="${NS.soap}"`,
    `xmlns:ns3="${NS.wsse}"`,
    `xmlns:u="${NS.wsu}"`,
  ];
  for (const decl of required) {
    if (!timestampC14n.includes(decl)) {
      throw new Error(`Timestamp canonical form missing ${decl} (build=${TS_BUILD_TAG})`);
    }
  }

  console.log(`TIMESTAMP_BUILD_TAG: ${TS_BUILD_TAG}`);
  console.log('TIMESTAMP_C14N:', timestampC14n);
  console.log('TIMESTAMP_BYTES:', Buffer.byteLength(timestampC14n, 'utf8'));
  console.log('TIMESTAMP_HAS_DEFAULT_XMLNS:', timestampC14n.includes(`xmlns="${NS.soap}"`));
  console.log('TIMESTAMP_HAS_NS3:', timestampC14n.includes(`xmlns:ns3="${NS.wsse}"`));
  console.log('TIMESTAMP_HAS_U:', timestampC14n.includes(`xmlns:u="${NS.wsu}"`));
  const timestampDigest = crypto.createHash('sha256').update(timestampC14n, 'utf8').digest('base64');
  console.log('TIMESTAMP_DIGEST:', timestampDigest);

  // Step 2 — build SignedInfo with explicit URIs + InclusiveNamespaces children.
  const signedInfoXml =
    `<SignedInfo xmlns="${NS.dsig}">` +
    `<CanonicalizationMethod Algorithm="${C14N_INCL_WITH_COMMENTS}"/>` +
    `<SignatureMethod Algorithm="${SIG_RSA_SHA256}"/>` +
    buildReferenceXml(mefHeaderId, '#default u', mefHeaderDigest) +
    buildReferenceXml(bodyId, '#default u', bodyDigest) +
    buildReferenceXml(timestampId, 'ns3 #default u', timestampDigest) +
    `</SignedInfo>`;

  const keyInfoXml =
    `<KeyInfo Id="${keyInfoId}">` +
    `<wsse:SecurityTokenReference xmlns:wsu="${NS.wsu}" wsu:Id="${strId}" xmlns:wsse="${NS.wsse}">` +
    `<wsse:Reference URI="#${x509Id}" ValueType="${X509_VALUE_TYPE}"/>` +
    `</wsse:SecurityTokenReference>` +
    `</KeyInfo>`;

  const signatureXml =
    `<Signature xmlns="${NS.dsig}" Id="${sigId}">` +
    signedInfoXml +
    `<SignatureValue>${SIGNATURE_VALUE_PLACEHOLDER}</SignatureValue>` +
    keyInfoXml +
    `</Signature>`;

  // Step 3 — assemble the complete envelope with Signature between BST and Timestamp.
  const fullEnvelope = digestEnvelope.replace(
    '</wsse:BinarySecurityToken>',
    '</wsse:BinarySecurityToken>' + signatureXml
  );

  // Step 4 — canonicalize SignedInfo in its real document context (inclusive c14n w/ comments),
  // RSA-SHA256 sign, then splice the signature value into the envelope bytes.
  const fullDoc = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
  }).parseFromString(fullEnvelope);
  const signedInfoEl = findFirstByLocalName(fullDoc, 'SignedInfo');
  if (!signedInfoEl) {
    throw new Error('buildLoginEnvelope: failed to locate SignedInfo for canonicalization');
  }
  const rawC14n = new C14nCanonicalizationWithComments().process(signedInfoEl, {});

  // xml-crypto's inclusive c14n doesn't emit ancestor namespace declarations
  // that aren't visibly utilized in the subtree — so the canonical SignedInfo
  // is missing xmlns:u (declared on <Envelope>) and xmlns:ns3 (declared on
  // <ns3:Security>). IRS's spec-correct verifier pulls both into the apex,
  // so their canonical form differs from ours and the RSA signature fails.
  // Splice the two missing declarations into the opening <SignedInfo> tag.
  // Order per c14n spec: default xmlns first, then prefixed alphabetically.
  // Everything else (attribute escaping, expanded empty tags, Reference
  // content) is already correct from xml-crypto's output.
  const SIGNEDINFO_BUILD_TAG = 'signedinfo-c14n-v2-splice-ancestor-ns';
  const originalOpener = `<SignedInfo xmlns="${NS.dsig}">`;
  const patchedOpener = `<SignedInfo xmlns="${NS.dsig}" xmlns:ns3="${NS.wsse}" xmlns:u="${NS.wsu}">`;
  if (!rawC14n.startsWith(originalOpener)) {
    throw new Error(`SignedInfo canonical form did not start with expected opener (build=${SIGNEDINFO_BUILD_TAG})`);
  }
  const canonicalSignedInfo = originalOpener === patchedOpener
    ? rawC14n
    : patchedOpener + rawC14n.slice(originalOpener.length);

  console.log(`SIGNEDINFO_BUILD_TAG: ${SIGNEDINFO_BUILD_TAG}`);
  console.log('SIGNEDINFO_C14N:', canonicalSignedInfo);
  console.log('SIGNEDINFO_BYTES:', Buffer.byteLength(canonicalSignedInfo, 'utf8'));
  console.log('SIGNEDINFO_HAS_DSIG_XMLNS:', canonicalSignedInfo.includes(`xmlns="${NS.dsig}"`));
  console.log('SIGNEDINFO_HAS_U:', canonicalSignedInfo.includes(`xmlns:u="${NS.wsu}"`));
  console.log('SIGNEDINFO_HAS_NS3:', canonicalSignedInfo.includes(`xmlns:ns3="${NS.wsse}"`));

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(canonicalSignedInfo, 'utf8');
  const signatureValue = signer.sign(privateKey, 'base64');

  const signedXml = fullEnvelope.replace(SIGNATURE_VALUE_PLACEHOLDER, signatureValue);

  return {
    xml: signedXml,
    messageId,
    ids: { mefHeaderId, bodyId, timestampId, x509Id, sigId, keyInfoId, strId },
  };
}

/**
 * Build the SendSubmissions SOAP envelope (matches SendSamp-LR.txt).
 * No signing by us — the SAML assertion is IRS-issued and already self-signed.
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
