// In-memory SAML session cache. Single instance per process — Railway can run
// multiple replicas so callers should not assume this is shared across dynos.
// For our volume this is acceptable; each replica logs in independently.

let cached = null; // { samlAssertionXml, notOnOrAfter: Date, storedAt: Date, rawLoginResponse }

// Refresh when fewer than 5 minutes remain on the SAML validity window.
const REFRESH_WINDOW_MS = 5 * 60 * 1000;

function setSamlAssertion({ samlAssertionXml, notOnOrAfter, rawLoginResponse }) {
  cached = {
    samlAssertionXml,
    notOnOrAfter: notOnOrAfter ? new Date(notOnOrAfter) : null,
    storedAt: new Date(),
    rawLoginResponse,
  };
}

function getSamlAssertion() {
  if (!cached) return null;
  if (cached.notOnOrAfter && cached.notOnOrAfter.getTime() - Date.now() < REFRESH_WINDOW_MS) {
    return null;
  }
  return cached;
}

function clearSamlAssertion() {
  cached = null;
}

module.exports = { setSamlAssertion, getSamlAssertion, clearSamlAssertion };
