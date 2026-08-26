// FlareHub - Stateless Auth-Helfer (kein Cookie!)
// Login-Token & Admin-Grant leben NUR im sessionStorage (pro Browser-Session,
// kein Persistieren auf der Platte). Bei jedem Request werden sie als Header
// mitgeschickt. Neuer Browser-Besuch = sessionStorage leer = erneuter
// PIN-/Passkey-Login erforderlich.

const AUTH_TOKEN_KEY = 'flarehub_token';
const ADMIN_GRANT_KEY = 'flarehub_admin_grant';
const REVEAL_IPS_KEY = 'flarehub_reveal_ips';

// Endpunkte, die auch bei gültiger Session legitime 401-Antworten liefern
// (z.B. falsche PIN auf der Login-Seite) - dort NICHT automatisch weiterleiten.
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

// Privacy: IP-Maskierung im Security-Feed nur mit aktivem Admin-Grant deaktivierbar
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

// Fetch-Wrapper: haengt Authorization-, Admin-Grant- und Reveal-IPs-Header an und
// leitet bei abgelaufenem Token automatisch zum Login weiter.
async function authFetch(url, options = {}) {
    const opts = Object.assign({}, options);
    opts.headers = Object.assign({}, options.headers || {});
    const token = getAuthToken();
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    const grant = getAdminGrant();
    if (grant) opts.headers['X-Admin-Grant'] = grant;
    if (getRevealIps()) opts.headers['X-Reveal-IPs'] = '1';

    const res = await fetch(url, opts);

    const path = new URL(url, window.location.origin).pathname;
    if (res.status === 401 && token && !LOGIN_FLOW_ENDPOINTS.includes(path)) {
        clearAuth();
        window.location.href = '/login';
        throw new Error('Nicht authentifiziert');
    }
    return res;
}

function logout() {
    clearAuth();
    window.location.href = '/login';
}
