const express = require('express');
const fetch = require('node-fetch');
const { loginMeF, sendSubmissions, getAcknowledgements } = require('./lib/mefClient');

const app = express();
app.use(express.json({ limit: '10mb' }));

function requireProxyKey(req, res) {
  const key = req.headers['x-proxy-key'];
  if (!key || key !== process.env.PROXY_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return false;
  }
  return true;
}

// Legacy generic pass-through — retained so callers still using it keep working
// while we migrate off. New MeF traffic should use /mef/* endpoints below.
app.post('/proxy', async (req, res) => {
  if (!requireProxyKey(req, res)) return;
  const { url, soapEnvelope, headers } = req.body;
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml;charset=UTF-8',
        'SOAPAction': '',
        ...headers,
      },
      body: soapEnvelope,
    });
    const body = await response.text();
    res.status(response.status).send(body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Isolated Login test — lets us verify X.509 signing against IRS ATS before
// attempting SendSubmissions. Returns the raw request + response envelopes.
app.post('/mef/login', async (req, res) => {
  if (!requireProxyKey(req, res)) return;
  try {
    const result = await loginMeF();
    res.status(result.success ? 200 : 502).json({
      success: result.success,
      messageId: result.messageId,
      ids: result.ids,
      request: result.request,
      responseStatus: result.response.status,
      responseHeaders: result.response.headers,
      responseBody: result.response.body,
      durationMs: result.response.durationMs,
      samlNotOnOrAfter: result.samlAssertion ? result.samlAssertion.notOnOrAfter : null,
    });
  } catch (err) {
    console.error('[mef-proxy] /mef/login error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// SendSubmissions — expects { submissionId, electronicPostmarkTs, zipBase64 }.
// The ZIP is transmitted as a base64-encoded string in JSON; the proxy decodes
// it to a Buffer and wraps it as MIME Part 2. If no SAML is cached, logs in
// first so the SendSubmissions envelope can carry a valid assertion.
app.post('/mef/send-submissions', async (req, res) => {
  if (!requireProxyKey(req, res)) return;
  try {
    const { submissionId, electronicPostmarkTs, zipBase64 } = req.body || {};
    if (!submissionId || !electronicPostmarkTs || !zipBase64) {
      return res.status(400).json({
        success: false,
        error: 'submissionId, electronicPostmarkTs, and zipBase64 are required',
      });
    }
    const zipBuffer = Buffer.from(zipBase64, 'base64');
    if (zipBuffer.length === 0) {
      return res.status(400).json({ success: false, error: 'zipBase64 decoded to empty buffer' });
    }
    const result = await sendSubmissions({ submissionId, electronicPostmarkTs, zipBuffer });
    res.status(result.success ? 200 : 502).json({
      success: result.success,
      messageId: result.messageId,
      submissionId: result.submissionId,
      request: result.request,
      mimeBoundary: result.mimeBoundary,
      mimeTotalBytes: result.mimeTotalBytes,
      responseStatus: result.response.status,
      responseHeaders: result.response.headers,
      responseBody: result.response.body,
      durationMs: result.response.durationMs,
    });
  } catch (err) {
    console.error('[mef-proxy] /mef/send-submissions error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GetAcknowledgements — given { submissionIds: [...] }, poll IRS for the
// actual accept/reject verdict of each submission. Returns the raw SOAP
// response body so the caller can parse it however they want (the Supabase
// `get-mef-acks` edge function parses StatusCd + ErrorList per submission).
app.post('/mef/get-acks', async (req, res) => {
  if (!requireProxyKey(req, res)) return;
  try {
    const { submissionIds, schemaVariant, endpointVariant, soapActionVariant, envelopeMode } = req.body || {};
    if (!Array.isArray(submissionIds) || submissionIds.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'submissionIds (non-empty array) is required',
      });
    }
    const result = await getAcknowledgements({
      submissionIds,
      schemaVariant,
      endpointVariant,
      soapActionVariant,
      envelopeMode,
    });
    res.status(result.success ? 200 : 502).json({
      success: result.success,
      messageId: result.messageId,
      submissionIds: result.submissionIds,
      envelopeMode: result.envelopeMode,
      schemaVariant: result.schemaVariant,
      endpointVariant: result.endpointVariant,
      endpointUrl: result.endpointUrl,
      operationName: result.operationName,
      soapActionVariant: result.soapActionVariant,
      soapAction: result.soapAction,
      transport: result.transport, // was missing — edge function saw transport:null even when MIME was used
      request: result.request,
      responseStatus: result.response.status,
      responseHeaders: result.response.headers,
      responseBody: result.response.body,
      durationMs: result.response.durationMs,
    });
  } catch (err) {
    console.error('[mef-proxy] /mef/get-acks error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/health', (_req, res) => res.json({
  ok: true,
  version: '2.0.0',
  // Real IRS operation is GetAcks, not GetAcknowledgements. Confirmed via
  // prd_endpoints.properties. Default is now `get_acks_mime` which
  // resolves to /a2a/mef/mime/GetAcks with SOAPAction=GetAcks.
  getAcksEndpointVariants: [
    'get_acks_mime', 'get_ack_mime', 'get_new_acks_mime',
    'mime', 'direct', 'msi_services', 'msi_lowercase',
    'msi_services_root', 'get_acks', 'transmitter',
    'mime_root', 'login_path', 'mefservices',
  ],
  getAcksDefaultVariant: 'get_acks_mime',
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`mef-proxy listening on :${PORT}`));
