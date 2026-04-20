// In-memory SAML session cache. Single instance per process — Railway can run
// multiple replicas so callers should not assume this is shared across dynos.
// For our volume this is acceptable; each replica logs in independently.

let cached = null; // { samlAssertionXml, notOnOrAfter: Date, storedAt: Date, rawLoginResponse }

// Force a fresh Login when fewer than 5 minutes remain on the SAML assertion's
// NotOnOrAfter window. IRS will reject a SendSubmissions whose SAML is expired
// OR within its final few minutes (clock-skew margin on their side).
const REFRESH_WINDOW_MS = 5 * 60 * 1000;

function setSamlAssertion({ samlAssertionXml, notOnOrAfter, rawLoginResponse }) {
  cached = {
    samlAssertionXml,
    notOnOrAfter: notOnOrAfter ? new Date(notOnOrAfter) : null,
    storedAt: new Date(),
    rawLoginResponse,
  };
  if (!cached.notOnOrAfter || isNaN(cached.notOnOrAfter.getTime())) {
    console.warn(
      '[mef-proxy] SAML cached without a valid NotOnOrAfter — session will be treated as expired and a fresh Login will be forced on next call.'
    );
  } else {
    console.log(
      `[mef-proxy] SAML cached. notOnOrAfter=${cached.notOnOrAfter.toISOString()} (valid for ${Math.round((cached.notOnOrAfter.getTime() - Date.now()) / 60000)} min)`
    );
  }
}

function getSamlAssertion() {
  if (!cached) return null;

  // No expiry attached → we can't trust the session. Force a fresh Login.
  if (!cached.notOnOrAfter || isNaN(cached.notOnOrAfter.getTime())) {
    console.log('[mef-proxy] SAML cache has no NotOnOrAfter — forcing fresh Login.');
    cached = null;
    return null;
  }

  const msUntilExpiry = cached.notOnOrAfter.getTime() - Date.now();
  if (msUntilExpiry < REFRESH_WINDOW_MS) {
    console.log(
      `[mef-proxy] SAML session expiring in ${Math.round(msUntilExpiry / 1000)}s (<5min window) — forcing fresh Login.`
    );
    cached = null;
    return null;
  }

  console.log(
    `[mef-proxy] SAML cache hit. ${Math.round(msUntilExpiry / 60000)} min remaining until NotOnOrAfter.`
  );
  return cached;
}

function clearSamlAssertion() {
  cached = null;
}

module.exports = { setSamlAssertion, getSamlAssertion, clearSamlAssertion };
