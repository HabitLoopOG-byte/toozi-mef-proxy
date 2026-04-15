const express = require('express');
const fetch = require('node-fetch');
const app = express();

app.use(express.json({ limit: '10mb' }));

app.post('/proxy', async (req, res) => {
  const proxyKey = req.headers['x-proxy-key'];
  if (proxyKey !== process.env.PROXY_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { url, soapEnvelope, headers } = req.body;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml;charset=UTF-8',
        'SOAPAction': '',
        ...headers
      },
      body: soapEnvelope
    });

    const body = await response.text();
    res.status(response.status).send(body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`mef-proxy listening on :${PORT}`));
