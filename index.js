const express = require('express');
const fetch = require('node-fetch');
const { loginMeF, sendSubmissions } = require('./lib/mefClient');

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

// SendSubmissions — expects { submissions: [{ submissionId, electronicPostmarkTs }] }.
// Performs a Login first if no cached SAML is available.
app.post('/mef/send-submissions', async (req, res) => {
  if (!requireProxyKey(req, res)) return;
  try {
    const { submissions } = req.body || {};
    if (!Array.isArray(submissions) || submissions.length === 0) {
      return res.status(400).json({ success: false, error: 'submissions array required' });
    }
    const result = await sendSubmissions({ submissions });
    res.status(result.success ? 200 : 502).json({
      success: result.success,
      messageId: result.messageId,
      request: result.request,
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

app.get('/health', (_req, res) => res.json({ ok: true, version: '1.1.0' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`mef-proxy listening on :${PORT}`));
