// FlareHub - stateless auth helpers (no cookie!)
// Login token & admin grant live ONLY in the sessionStorage (per browser session,
// no persistence on disk). They are sent as headers on every request.
// New browser visit = empty sessionStorage = fresh PIN/passkey login required.

const AUTH_TOKEN_KEY = 'flarehub_token';
const ADMIN_GRANT_KEY = 'flarehub_admin_grant';
const REVEAL_IPS_KEY = 'flarehub_reveal_ips';

// Endpoints that legitimately return 401 even with a valid session
// (e.g. wrong PIN on the login page) - do NOT redirect there automatically.
const LOGIN_FLOW_ENDPOINTS = [
    '/api/auth/status',
    '/api/auth/verify-pin',
    '/api/passkey/auth-options',
    '/api/passkey/auth-verify'
];

function getAuthToken() {
    return sessionStorage.getItem(AUTH_TOKEN_KEY);
}

function setAuthToken(token) {
    sessionStorage.setItem(AUTH_TOKEN_KEY, token);
}

function getAdminGrant() {
    return sessionStorage.getItem(ADMIN_GRANT_KEY);
}

function setAdminGrant(grant) {
    sessionStorage.setItem(ADMIN_GRANT_KEY, grant);
}

// Privacy: IP masking in the security feed can only be disabled with an active admin grant
function getRevealIps() {
    return sessionStorage.getItem(REVEAL_IPS_KEY) === '1';
}

function setRevealIps(enabled) {
    if (enabled) sessionStorage.setItem(REVEAL_IPS_KEY, '1');
    else sessionStorage.removeItem(REVEAL_IPS_KEY);
}

function clearAuth() {
    sessionStorage.removeItem(AUTH_TOKEN_KEY);
    sessionStorage.removeItem(ADMIN_GRANT_KEY);
    sessionStorage.removeItem(REVEAL_IPS_KEY);
}

// Fetch wrapper: attaches Authorization, admin-grant and reveal-IPs headers and
// redirects to the login page automatically when the token has expired.
// All requests get a hard timeout (default 30 s) so buttons/UI can never hang forever.
async function authFetch(url, options = {}) {
    const opts = Object.assign({}, options);
    opts.headers = Object.assign({}, options.headers || {});
    const token = getAuthToken();
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    const grant = getAdminGrant();
    if (grant) opts.headers['X-Admin-Grant'] = grant;
    if (getRevealIps()) opts.headers['X-Reveal-IPs'] = '1';

    const timeoutMs = options.timeoutMs || 30000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, Object.assign(opts, { signal: controller.signal }));

        const path = new URL(url, window.location.origin).pathname;
        if (res.status === 401 && token && !LOGIN_FLOW_ENDPOINTS.includes(path)) {
            clearAuth();
            window.location.href = '/login';
            throw new Error('Not authenticated');
        }
        return res;
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new Error('Request timed out after ' + Math.round(timeoutMs / 1000) + 's');
        }
        throw err;
    } finally {
        clearTimeout(timer);
    }
}

function logout() {
    clearAuth();
    window.location.href = '/login';
}
