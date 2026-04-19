const crypto = require('crypto');

// 32-char uppercase hex, matching the sample: ESTPerfAssurance-MeFHeader-392E0F082E07495DABD314D890781011
function hex32() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function generateXmlId(kind) {
  return `ESTPerfAssurance-${kind}-${hex32()}`;
}

// MessageID format: ETIN (5) + timestamp compact + random suffix — 20 chars per sample
// Sample: 10748202610511811157 (ETIN=10748 + 15 chars)
function generateMessageId(etin) {
  const now = new Date();
  const yyyy = String(now.getUTCFullYear());
  const doy = String(
    Math.floor(
      (Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) -
        Date.UTC(now.getUTCFullYear(), 0, 0)) / 86400000
    )
  ).padStart(3, '0');
  const hh = String(now.getUTCHours()).padStart(2, '0');
  const mm = String(now.getUTCMinutes()).padStart(2, '0');
  const ss = String(now.getUTCSeconds()).padStart(2, '0');
  const rand = String(crypto.randomInt(0, 10000)).padStart(4, '0');
  return `${etin}${yyyy}${doy}${hh}${mm}${ss}${rand}`;
}

module.exports = { generateXmlId, generateMessageId };
