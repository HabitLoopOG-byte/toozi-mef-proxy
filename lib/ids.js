const crypto = require('crypto');

// 32-char uppercase hex, matching the sample: ESTPerfAssurance-MeFHeader-392E0F082E07495DABD314D890781011
function hex32() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function generateXmlId(kind) {
  return `ESTPerfAssurance-${kind}-${hex32()}`;
}

// MessageID — exactly 20 numeric chars per IRS MeF spec.
// Layout: ETIN (5) + year (4) + month (2) + day (2) + random (7) = 20.
// IRS rejects any other length with "Incorrect length for Message ID".
const MESSAGE_ID_LENGTH = 20;
function generateMessageId(etin) {
  const now = new Date();
  const yyyy = String(now.getUTCFullYear());
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  const prefix = `${etin}${yyyy}${mm}${dd}`;
  const randLen = MESSAGE_ID_LENGTH - prefix.length;
  if (randLen < 1) {
    throw new Error(`generateMessageId: ETIN "${etin}" produces prefix longer than ${MESSAGE_ID_LENGTH} chars`);
  }
  let rand = '';
  for (let i = 0; i < randLen; i++) {
    rand += String(crypto.randomInt(0, 10));
  }
  return `${prefix}${rand}`;
}

module.exports = { generateXmlId, generateMessageId };
