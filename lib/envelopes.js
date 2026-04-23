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

// Extract the base64-encoded DER body of the FIRST certificate block. Anything
// outside the BEGIN/END CERTIFICATE markers (Bag Attributes headers, subject/
// issuer metadata from openssl dumps, trailing chain certs) is ignored — the
// BinarySecurityToken must contain only the raw base64-encoded DER bytes.
function extractBase64Cert(pem) {
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!match) {
    throw new Error('extractBase64Cert: no PEM CERTIFICATE block found');
  }
  return match[1].replace(/\s+/g, '');
}

// TestCd MUST match the target URL environment. IRS e-Help Desk:
//   ATS  → URL la.alt.www4.irs.gov → TestCd=T
//   PROD → URL la.www4.irs.gov     → TestCd=P
// This proxy is hardcoded to the ATS URL in mefClient.js, so TestCd is
// hardcoded to "T" here. Moving to production requires flipping BOTH values
// together in one commit — never allow the URL host and TestCd to drift.
// (The LoginSamp-LR.txt sample IRS ships shows "P" because the sample was
// captured against their Production environment; don't copy that field
// verbatim for ATS.)
const TEST_CD_ATS = 'T';

function buildMeFHeaderXml({ action, messageId, messageTs, etin, appSysId, clientSoftwareTxt, wsuId }) {
  return (
    `<MeFHeader xmlns="${NS.mefhdr}" xmlns:xsd="${NS.xsd}" xmlns:xsi="${NS.xsi}" Id="MefHeader" u:Id="${wsuId}">` +
    `<MessageID>${messageId}</MessageID>` +
    `<Action>${action}</Action>` +
    `<MessageTs>${messageTs}</MessageTs>` +
    `<ETIN>${etin}</ETIN>` +
    `<SessionKeyCd>Y</SessionKeyCd>` +
    `<TestCd>${TEST_CD_ATS}</TestCd>` +
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

  // Self-verify diagnostic — confirm the private key actually matches the
  // certificate we're sending in the BinarySecurityToken. If this returns
  // false, the IDENTRUST_CERT_B64 and IDENTRUST_KEY_B64 env vars are
  // mismatched and IRS's verifier (which extracts the public key from our
  // BST) will reject every signature regardless of canonicalization.
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(canonicalSignedInfo, 'utf8');
    const selfVerify = verifier.verify(cert, signatureValue, 'base64');
    console.log('SIGNATURE_SELF_VERIFY:', selfVerify);
    if (!selfVerify) {
      console.log('SIGNATURE_SELF_VERIFY_FAIL: private key does not match cert public key — check IDENTRUST_CERT_B64 vs IDENTRUST_KEY_B64');
    }
  } catch (verifyErr) {
    console.log('SIGNATURE_SELF_VERIFY_ERROR:', verifyErr.message);
  }
  try {
    const x509 = new crypto.X509Certificate(cert);
    console.log('CERT_SUBJECT:', x509.subject);
    console.log('CERT_ISSUER:', x509.issuer);
    console.log('CERT_VALID_FROM:', x509.validFrom);
    console.log('CERT_VALID_TO:', x509.validTo);
    console.log('CERT_SERIAL:', x509.serialNumber);
    console.log('CERT_KEY_TYPE:', x509.publicKey.asymmetricKeyType);
    console.log('CERT_KEY_SIZE:', x509.publicKey.asymmetricKeyDetails?.modulusLength);
  } catch (certErr) {
    console.log('CERT_PARSE_ERROR:', certErr.message);
  }

  // Build a second, independent canonical SignedInfo from scratch so we can
  // diff xml-crypto's output against a spec-literal construction. If they
  // differ, xml-crypto has a c14n bug we're inheriting.
  const handBuiltReference = (uri, prefixList, digestValue) =>
    `<Reference URI="#${uri}">` +
    `<Transforms>` +
    `<Transform Algorithm="${C14N_EXC}">` +
    `<InclusiveNamespaces xmlns="${NS.excc14n}" PrefixList="${prefixList}"></InclusiveNamespaces>` +
    `</Transform>` +
    `</Transforms>` +
    `<DigestMethod Algorithm="${DIGEST_SHA256}"></DigestMethod>` +
    `<DigestValue>${digestValue}</DigestValue>` +
    `</Reference>`;
  const handBuiltSignedInfo =
    `<SignedInfo xmlns="${NS.dsig}" xmlns:ns3="${NS.wsse}" xmlns:u="${NS.wsu}">` +
    `<CanonicalizationMethod Algorithm="${C14N_INCL_WITH_COMMENTS}"></CanonicalizationMethod>` +
    `<SignatureMethod Algorithm="${SIG_RSA_SHA256}"></SignatureMethod>` +
    handBuiltReference(mefHeaderId, '#default u', mefHeaderDigest) +
    handBuiltReference(bodyId, '#default u', bodyDigest) +
    handBuiltReference(timestampId, 'ns3 #default u', timestampDigest) +
    `</SignedInfo>`;
  console.log('SIGNEDINFO_DIFF_BUILD_TAG: signedinfo-diff-v1');
  console.log('SIGNEDINFO_HANDBUILT:', handBuiltSignedInfo);
  console.log('SIGNEDINFO_HANDBUILT_BYTES:', Buffer.byteLength(handBuiltSignedInfo, 'utf8'));
  console.log('SIGNEDINFO_HANDBUILT_EQUALS_SIGNED:', handBuiltSignedInfo === canonicalSignedInfo);
  if (handBuiltSignedInfo !== canonicalSignedInfo) {
    const a = handBuiltSignedInfo;
    const b = canonicalSignedInfo;
    const len = Math.min(a.length, b.length);
    let diffAt = -1;
    for (let i = 0; i < len; i++) {
      if (a.charCodeAt(i) !== b.charCodeAt(i)) { diffAt = i; break; }
    }
    if (diffAt === -1 && a.length !== b.length) diffAt = len;
    console.log('SIGNEDINFO_DIFF_AT:', diffAt, `(handbuilt=${a.length}, signed=${b.length})`);
    console.log('SIGNEDINFO_HANDBUILT_CTX:', JSON.stringify(a.slice(Math.max(0, diffAt - 40), diffAt + 40)));
    console.log('SIGNEDINFO_SIGNED_CTX:',    JSON.stringify(b.slice(Math.max(0, diffAt - 40), diffAt + 40)));
  }

  // Also extract the wire Signature block so we can see what IRS receives.
  const wireSigMatch = fullEnvelope.match(/<Signature\b[^>]*>[\s\S]*?<\/Signature>/);
  console.log('WIRE_SIGNATURE_BLOCK:', wireSigMatch ? wireSigMatch[0] : '(not found)');

  const signedXml = fullEnvelope.replace(SIGNATURE_VALUE_PLACEHOLDER, signatureValue);

  // Diagnostic — extract the actual <u:Timestamp> element from the wire envelope
  // and diff it against the hand-built canonical string we hashed. IRS canonicalizes
  // the wire element on their side; if spec-correct exc-c14n of the wire produces
  // a different byte sequence than our hand-built canonical form, the digest will
  // mismatch regardless of anything else we've done.
  const wireMatch = signedXml.match(/<u:Timestamp\b[^>]*>[\s\S]*?<\/u:Timestamp>/);
  const wireTimestamp = wireMatch ? wireMatch[0] : '(not found)';
  console.log('WIRE_TIMESTAMP_BUILD_TAG: wire-vs-canonical-diff-v1');
  console.log('WIRE_TIMESTAMP_RAW:', wireTimestamp);
  console.log('WIRE_TIMESTAMP_BYTES:', Buffer.byteLength(wireTimestamp, 'utf8'));
  console.log('HANDBUILT_TIMESTAMP_C14N:', timestampC14n);
  console.log('HANDBUILT_TIMESTAMP_BYTES:', Buffer.byteLength(timestampC14n, 'utf8'));

  // Simulate spec-correct exc-c14n of the wire Timestamp: take the wire form
  // and inject the three namespaces that IRS's verifier pulls from ancestor
  // scope (xmlns default, xmlns:ns3, xmlns:u) per PrefixList="ns3 #default u".
  // If THIS equals our hand-built string, the digest is mathematically
  // guaranteed to match. If it differs, the diff points to the bug.
  const wireOpenerMatch = wireTimestamp.match(/^<u:Timestamp\b([^>]*)>/);
  const wireAttrs = wireOpenerMatch ? wireOpenerMatch[1] : '';
  const specCanonicalWire = wireTimestamp.replace(
    /^<u:Timestamp\b[^>]*>/,
    `<u:Timestamp xmlns="${NS.soap}" xmlns:ns3="${NS.wsse}" xmlns:u="${NS.wsu}"${wireAttrs}>`
  );
  console.log('WIRE_AS_IRS_WOULD_CANONICALIZE:', specCanonicalWire);
  console.log('MATCHES_HANDBUILT:', specCanonicalWire === timestampC14n);
  if (specCanonicalWire !== timestampC14n) {
    // Find first differing character position
    const a = specCanonicalWire;
    const b = timestampC14n;
    let diffAt = -1;
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      if (a.charCodeAt(i) !== b.charCodeAt(i)) { diffAt = i; break; }
    }
    if (diffAt === -1 && a.length !== b.length) diffAt = len;
    console.log('FIRST_DIFF_AT:', diffAt);
    console.log('WIRE_CTX_AT_DIFF:', JSON.stringify(a.slice(Math.max(0, diffAt - 30), diffAt + 30)));
    console.log('HANDBUILT_CTX_AT_DIFF:', JSON.stringify(b.slice(Math.max(0, diffAt - 30), diffAt + 30)));
  }

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

/**
 * Build the GetAcknowledgements SOAP envelope.
 *
 * GetAcknowledgements is how we poll the IRS for the actual accept/reject
 * status of a previously-sent submission. SendSubmissions gives us a
 * ReceiptId (DepositId) but that's just "we received the bytes" — the real
 * verdict comes minutes later from GetAcknowledgements.
 *
 * No MIME multipart here — this is a plain SOAP envelope. SAML assertion
 * comes from the cached Login, same as SendSubmissions; we don't re-sign.
 *
 * ## Schema variants
 *
 * MeF's WSDL has drifted across IRS revisions and the exact wrapper names
 * have differed in various reference docs. The first live ATS call with
 * the `default` variant returned 20/20 not_found despite IRS confirming
 * 17 rejects exist — suggesting the element name or structure is wrong.
 * This builder supports three candidates so the operator can A/B them:
 *
 *   'default'  (as documented in Pub 4164 v2024):
 *     <GetAcknowledgementsRequest>
 *       <SubmissionIdList>
 *         <SubmissionId>X</SubmissionId>
 *       </SubmissionIdList>
 *     </GetAcknowledgementsRequest>
 *
 *   'lst'  (abbreviated element name — used in some older sample envelopes):
 *     <GetAcknowledgementsRequest>
 *       <SubmissionIdLst>
 *         <SubmissionId>X</SubmissionId>
 *       </SubmissionIdLst>
 *     </GetAcknowledgementsRequest>
 *
 *   'lst_cnt'  (abbreviated + explicit count — matches MeFMSI schema
 *               examples where the count is required):
 *     <GetAcknowledgementsRequest>
 *       <SubmissionIdCnt>N</SubmissionIdCnt>
 *       <SubmissionIdLst>
 *         <SubmissionId>X</SubmissionId>
 *       </SubmissionIdLst>
 *     </GetAcknowledgementsRequest>
 */
function buildGetAcknowledgementsEnvelope({
  etin,
  appSysId,
  clientSoftwareTxt = 'Toozi',
  samlAssertionXml,
  submissionIds,
  schemaVariant = 'default',
}) {
  if (!etin || !appSysId || !samlAssertionXml || !Array.isArray(submissionIds) || submissionIds.length === 0) {
    throw new Error('buildGetAcknowledgementsEnvelope: etin, appSysId, samlAssertionXml, non-empty submissionIds required');
  }
  if (!['default', 'lst', 'lst_cnt'].includes(schemaVariant)) {
    throw new Error(`buildGetAcknowledgementsEnvelope: unknown schemaVariant "${schemaVariant}"`);
  }

  const messageTs = new Date().toISOString();
  const messageId = generateMessageId(etin);
  const mefHeaderId = generateXmlId('MeFHeader');

  const mefHeaderXml = buildMeFHeaderXml({
    action: 'GetAcknowledgements',
    messageId,
    messageTs,
    etin,
    appSysId,
    clientSoftwareTxt,
    wsuId: mefHeaderId,
  });

  const submissionIdXml = submissionIds
    .map((id) => `<SubmissionId>${id}</SubmissionId>`)
    .join('');

  let requestBody;
  if (schemaVariant === 'lst') {
    requestBody =
      `<GetAcknowledgementsRequest xmlns="${NS.mefmsi}">` +
      `<SubmissionIdLst>${submissionIdXml}</SubmissionIdLst>` +
      `</GetAcknowledgementsRequest>`;
  } else if (schemaVariant === 'lst_cnt') {
    requestBody =
      `<GetAcknowledgementsRequest xmlns="${NS.mefmsi}">` +
      `<SubmissionIdCnt>${submissionIds.length}</SubmissionIdCnt>` +
      `<SubmissionIdLst>${submissionIdXml}</SubmissionIdLst>` +
      `</GetAcknowledgementsRequest>`;
  } else {
    // default
    requestBody =
      `<GetAcknowledgementsRequest xmlns="${NS.mefmsi}">` +
      `<SubmissionIdList>${submissionIdXml}</SubmissionIdList>` +
      `</GetAcknowledgementsRequest>`;
  }

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
    requestBody +
    `</Body>` +
    `</Envelope>`;

  return { xml: envelope, messageId };
}

/**
 * Build + sign the GetAcknowledgements SOAP envelope (Pub 5830 §4.3.7).
 *
 * Unlike SendSubmissions (which uses the SAML assertion returned by Login),
 * GetAcknowledgements is a Transmitter Service call that IRS expects to be
 * X.509-signed with the IdenTrust cert — same WS-Security pattern as
 * Login. The first live ATS test used the unsigned SAML-only pattern and
 * got back a Lorem Ipsum HTML catch-all page, consistent with IRS's
 * front-door gateway rejecting the request for missing signature.
 *
 * This function mirrors buildLoginEnvelope's structure. All the
 * canonicalization quirks Login needed are load-bearing and are duplicated
 * here on purpose — if Login's c14n ever needs fixing, port the change
 * over by diffing against this function.
 */
function buildSignedGetAcknowledgementsEnvelope({
  etin,
  appSysId,
  clientSoftwareTxt = 'Toozi',
  cert,
  privateKey,
  submissionIds,
  schemaVariant = 'default',
}) {
  if (!etin || !appSysId || !cert || !privateKey) {
    throw new Error('buildSignedGetAcknowledgementsEnvelope: etin, appSysId, cert, privateKey all required');
  }
  if (!Array.isArray(submissionIds) || submissionIds.length === 0) {
    throw new Error('buildSignedGetAcknowledgementsEnvelope: non-empty submissionIds required');
  }
  if (!['default', 'lst', 'lst_cnt'].includes(schemaVariant)) {
    throw new Error(`buildSignedGetAcknowledgementsEnvelope: unknown schemaVariant "${schemaVariant}"`);
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
    action: 'GetAcknowledgements',
    messageId,
    messageTs,
    etin,
    appSysId,
    clientSoftwareTxt,
    wsuId: mefHeaderId,
  });

  // Request body varies by schemaVariant — same set as the unsigned builder
  // so the operator can A/B schema independently of signing.
  const submissionIdXml = submissionIds
    .map((id) => `<SubmissionId>${id}</SubmissionId>`)
    .join('');
  let requestBody;
  if (schemaVariant === 'lst') {
    requestBody =
      `<GetAcknowledgementsRequest xmlns="${NS.mefmsi}">` +
      `<SubmissionIdLst>${submissionIdXml}</SubmissionIdLst>` +
      `</GetAcknowledgementsRequest>`;
  } else if (schemaVariant === 'lst_cnt') {
    requestBody =
      `<GetAcknowledgementsRequest xmlns="${NS.mefmsi}">` +
      `<SubmissionIdCnt>${submissionIds.length}</SubmissionIdCnt>` +
      `<SubmissionIdLst>${submissionIdXml}</SubmissionIdLst>` +
      `</GetAcknowledgementsRequest>`;
  } else {
    requestBody =
      `<GetAcknowledgementsRequest xmlns="${NS.mefmsi}">` +
      `<SubmissionIdList>${submissionIdXml}</SubmissionIdList>` +
      `</GetAcknowledgementsRequest>`;
  }

  // Step 1 — digest envelope without Signature element.
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
    requestBody +
    `</Body>` +
    `</Envelope>`;

  const digestDoc = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
  }).parseFromString(digestEnvelope);

  const mefHeaderEl = findFirstByLocalName(digestDoc, 'MeFHeader');
  const bodyEl = findFirstByLocalName(digestDoc, 'Body');
  const timestampEl = findFirstByLocalName(digestDoc, 'Timestamp');
  if (!mefHeaderEl || !bodyEl || !timestampEl) {
    throw new Error('buildSignedGetAcknowledgementsEnvelope: failed to locate signed elements in template');
  }

  const mefHeaderDigest = excDigest(mefHeaderEl, '#default u');
  const bodyDigest = excDigest(bodyEl, '#default u');

  // Hand-build the Timestamp canonical form — xml-crypto's exc-c14n won't
  // emit inclusive-namespace prefixes that aren't visibly utilized in the
  // subtree, but IRS pulls them from ancestor scope. Order per c14n spec:
  // default xmlns first, then prefixed alphabetically.
  const timestampC14n =
    '<u:Timestamp' +
    ` xmlns="${NS.soap}"` +
    ` xmlns:ns3="${NS.wsse}"` +
    ` xmlns:u="${NS.wsu}"` +
    ` u:Id="${timestampId}">` +
    `<u:Created>${created}</u:Created>` +
    `<u:Expires>${expires}</u:Expires>` +
    '</u:Timestamp>';
  const timestampDigest = crypto.createHash('sha256').update(timestampC14n, 'utf8').digest('base64');

  // Step 2 — SignedInfo with explicit URIs + InclusiveNamespaces children.
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

  // Step 3 — assemble envelope with Signature between BST and Timestamp.
  const fullEnvelope = digestEnvelope.replace(
    '</wsse:BinarySecurityToken>',
    '</wsse:BinarySecurityToken>' + signatureXml
  );

  // Step 4 — canonicalize SignedInfo in document context, sign, splice.
  const fullDoc = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
  }).parseFromString(fullEnvelope);
  const signedInfoEl = findFirstByLocalName(fullDoc, 'SignedInfo');
  if (!signedInfoEl) {
    throw new Error('buildSignedGetAcknowledgementsEnvelope: failed to locate SignedInfo');
  }
  const rawC14n = new C14nCanonicalizationWithComments().process(signedInfoEl, {});

  // Splice the two ancestor namespaces (ns3, u) that IRS's verifier pulls
  // from enclosing scope but xml-crypto omits. Order per c14n spec.
  const originalOpener = `<SignedInfo xmlns="${NS.dsig}">`;
  const patchedOpener = `<SignedInfo xmlns="${NS.dsig}" xmlns:ns3="${NS.wsse}" xmlns:u="${NS.wsu}">`;
  if (!rawC14n.startsWith(originalOpener)) {
    throw new Error('SignedInfo canonical form did not start with expected opener');
  }
  const canonicalSignedInfo = patchedOpener + rawC14n.slice(originalOpener.length);

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(canonicalSignedInfo, 'utf8');
  const signatureValue = signer.sign(privateKey, 'base64');

  // Self-verify — mismatched cert/key env vars produce guaranteed rejection.
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(canonicalSignedInfo, 'utf8');
    const selfVerify = verifier.verify(cert, signatureValue, 'base64');
    if (!selfVerify) {
      console.log('[GET_ACKS_SIG] SELF_VERIFY_FAILED — cert/key mismatch; check IDENTRUST_CERT_B64 vs IDENTRUST_KEY_B64');
    }
  } catch (verifyErr) {
    console.log('[GET_ACKS_SIG] self-verify error:', verifyErr.message);
  }

  const signedXml = fullEnvelope.replace(SIGNATURE_VALUE_PLACEHOLDER, signatureValue);

  return {
    xml: signedXml,
    messageId,
    ids: { mefHeaderId, bodyId, timestampId, x509Id, sigId, keyInfoId, strId },
  };
}

/**
 * Build + sign the GetAcks SOAP envelope — the REAL IRS operation name.
 *
 * The earlier "GetAcknowledgements" naming was a misreading of Pub 5830 —
 * IRS's actual A2A operations use the abbreviated form "GetAcks". This is
 * confirmed by prd_endpoints.properties in the IRS A2A bundle:
 *
 *   GET_ACKS=la.www4.irs.gov/a2a/mef/mime/GetAcks
 *   GET_ACK=la.www4.irs.gov/a2a/mef/mime/GetAck
 *   GET_NEW_ACKS=la.www4.irs.gov/a2a/mef/mime/GetNewAcks
 *
 * URL, SOAPAction, MeFHeader <Action>, AND the request body wrapper
 * (<GetAcksRequest>) all use the "GetAcks" name.
 *
 * Signing pattern is identical to Login / GetAcknowledgements — all the
 * canonicalization quirks are load-bearing.
 */
function buildSignedGetAcksEnvelope({
  etin,
  appSysId,
  clientSoftwareTxt = 'Toozi',
  cert,
  privateKey,
  submissionIds,
  schemaVariant = 'default',
}) {
  if (!etin || !appSysId || !cert || !privateKey) {
    throw new Error('buildSignedGetAcksEnvelope: etin, appSysId, cert, privateKey all required');
  }
  if (!Array.isArray(submissionIds) || submissionIds.length === 0) {
    throw new Error('buildSignedGetAcksEnvelope: non-empty submissionIds required');
  }
  if (!['default', 'lst', 'lst_cnt'].includes(schemaVariant)) {
    throw new Error(`buildSignedGetAcksEnvelope: unknown schemaVariant "${schemaVariant}"`);
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
    action: 'GetAcks', // ← was 'GetAcknowledgements' — IRS rejected every URL because of this name
    messageId,
    messageTs,
    etin,
    appSysId,
    clientSoftwareTxt,
    wsuId: mefHeaderId,
  });

  const submissionIdXml = submissionIds
    .map((id) => `<SubmissionId>${id}</SubmissionId>`)
    .join('');
  // Namespace MUST be MeFTransmitterService.xsd (same as SendSubmissionsRequest),
  // NOT MeFMSIServices.xsd. IRS's actual SOAP fault on 2026-04-23:
  //   "IDP Rule 'ALT-MeF Invalid WSDL IDP Rule' aborted processing. The root
  //    element '{http://www.irs.gov/a2a/mef/MeFMSIServices.xsd}GetAcksRequest'
  //    ... does not match the name and namespace of any message in the WSDL."
  // Confirmed the Policy was `ALT-MeF-Transmitter-MIME` — GetAcks is a
  // Transmitter-service operation, so it shares meftrans with SendSubmissions.
  let requestBody;
  if (schemaVariant === 'lst') {
    requestBody =
      `<GetAcksRequest xmlns="${NS.meftrans}">` +
      `<SubmissionIdLst>${submissionIdXml}</SubmissionIdLst>` +
      `</GetAcksRequest>`;
  } else if (schemaVariant === 'lst_cnt') {
    requestBody =
      `<GetAcksRequest xmlns="${NS.meftrans}">` +
      `<SubmissionIdCnt>${submissionIds.length}</SubmissionIdCnt>` +
      `<SubmissionIdLst>${submissionIdXml}</SubmissionIdLst>` +
      `</GetAcksRequest>`;
  } else {
    requestBody =
      `<GetAcksRequest xmlns="${NS.meftrans}">` +
      `<SubmissionIdList>${submissionIdXml}</SubmissionIdList>` +
      `</GetAcksRequest>`;
  }

  // Step 1 — digest envelope without Signature element.
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
    requestBody +
    `</Body>` +
    `</Envelope>`;

  const digestDoc = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
  }).parseFromString(digestEnvelope);

  const mefHeaderEl = findFirstByLocalName(digestDoc, 'MeFHeader');
  const bodyEl = findFirstByLocalName(digestDoc, 'Body');
  const timestampEl = findFirstByLocalName(digestDoc, 'Timestamp');
  if (!mefHeaderEl || !bodyEl || !timestampEl) {
    throw new Error('buildSignedGetAcksEnvelope: failed to locate signed elements in template');
  }

  const mefHeaderDigest = excDigest(mefHeaderEl, '#default u');
  const bodyDigest = excDigest(bodyEl, '#default u');
  const timestampC14n =
    '<u:Timestamp' +
    ` xmlns="${NS.soap}"` +
    ` xmlns:ns3="${NS.wsse}"` +
    ` xmlns:u="${NS.wsu}"` +
    ` u:Id="${timestampId}">` +
    `<u:Created>${created}</u:Created>` +
    `<u:Expires>${expires}</u:Expires>` +
    '</u:Timestamp>';
  const timestampDigest = crypto.createHash('sha256').update(timestampC14n, 'utf8').digest('base64');

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

  const fullEnvelope = digestEnvelope.replace(
    '</wsse:BinarySecurityToken>',
    '</wsse:BinarySecurityToken>' + signatureXml
  );

  const fullDoc = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
  }).parseFromString(fullEnvelope);
  const signedInfoEl = findFirstByLocalName(fullDoc, 'SignedInfo');
  if (!signedInfoEl) {
    throw new Error('buildSignedGetAcksEnvelope: failed to locate SignedInfo');
  }
  const rawC14n = new C14nCanonicalizationWithComments().process(signedInfoEl, {});
  const originalOpener = `<SignedInfo xmlns="${NS.dsig}">`;
  const patchedOpener = `<SignedInfo xmlns="${NS.dsig}" xmlns:ns3="${NS.wsse}" xmlns:u="${NS.wsu}">`;
  if (!rawC14n.startsWith(originalOpener)) {
    throw new Error('SignedInfo canonical form did not start with expected opener');
  }
  const canonicalSignedInfo = patchedOpener + rawC14n.slice(originalOpener.length);

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(canonicalSignedInfo, 'utf8');
  const signatureValue = signer.sign(privateKey, 'base64');

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(canonicalSignedInfo, 'utf8');
    const selfVerify = verifier.verify(cert, signatureValue, 'base64');
    if (!selfVerify) {
      console.log('[GET_ACKS_SIG] SELF_VERIFY_FAILED — cert/key mismatch; check IDENTRUST_CERT_B64 vs IDENTRUST_KEY_B64');
    }
  } catch (verifyErr) {
    console.log('[GET_ACKS_SIG] self-verify error:', verifyErr.message);
  }

  const signedXml = fullEnvelope.replace(SIGNATURE_VALUE_PLACEHOLDER, signatureValue);

  return {
    xml: signedXml,
    messageId,
    ids: { mefHeaderId, bodyId, timestampId, x509Id, sigId, keyInfoId, strId },
  };
}

module.exports = {
  buildLoginEnvelope,
  buildSendSubmissionsEnvelope,
  buildGetAcknowledgementsEnvelope,         // legacy — kept for regression testing
  buildSignedGetAcknowledgementsEnvelope,   // legacy — kept for regression testing
  buildSignedGetAcksEnvelope,                // THE one IRS actually accepts
  extractBase64Cert,
  NS,
};
