# FlareHub – Security Audit

Stand: 2026-08-26 · Umfang: kompletter Codebestand (Backend, Templates, Docker-Setup, Abhängigkeiten)

FlareHub ist ein selbst gehostetes Dashboard für kritische Infrastruktur (Cloudflare-Zone-Steuerung).
Dieses Dokument fasst das Sicherheitsmodell, die durchgeführten Prüfungen und die offenen
Restrisiken zusammen.

---

## 1. Authentifizierungsmodell (stateless, kein Cookie)

- **Kein Session-Cookie.** Nach PIN-/Passkey-Login stellt der Server ein kurzlebiges,
  signiertes Token aus (itsdangerous, HMAC mit `SESSION_SECRET_KEY`). Das Frontend legt es
  ausschließlich im `sessionStorage` ab und sendet es bei jedem Request als
  `Authorization: Bearer <token>` mit.
- **Konsequenz:** Beim Schließen des Browsers ist der Token weg. Jeder neue Besuch
  erfordert einen erneuten PIN-/Passkey-Login. Es gibt keinen serverseitigen Session-Store,
  der kompromittiert oder gestohlen werden könnte.
- Token-Lebensdauer: `SESSION_EXPIRY_HOURS` (Standard 4 h) als oberes Limit.
- **Admin-Grant:** zusätzliche Hürde für die Passkey-Verwaltung. Ebenfalls kein Cookie –
  lebt nur im `sessionStorage` und wird als `X-Admin-Grant`-Header gesendet. Signiert,
  maximal 10 Minuten gültig. Der Admin-Token-Vergleich ist `hmac.compare_digest`
  (timing-safe), mit IP-basiertem Lockout wie beim PIN.
- **PIN:** nur als bcrypt-Hash gespeichert (`AUTH_PIN_HASH`), Vergleich über `bcrypt.checkpw`.
  Lockout nach `AUTH_PIN_MAX_ATTEMPTS` Fehlversuchen für `AUTH_PIN_LOCKOUT_SECONDS`
  (IP-basiert, in-memory). Standard-PIN-Länge: 6 Stellen (für kritische Infrastruktur
  6+ empfohlen, kürzer möglich über `AUTH_PIN_LENGTH`).
- **WebAuthn/Passkey:** RP-ID- und Origin-Validierung, Einmal-Challenges (werden nach
  Verwendung entfernt), Sign-Counter-Prüfung, optionale User-Verification
  (`WEBAUTHN_USER_VERIFICATION=required` erzwingt sie).

## 2. Prüfungen & Befunde (alles behoben)

| # | Befund | Schwere | Status |
|---|---|---|---|
| 1 | Passkey-Optionen doppelt JSON-encodiert (`options_to_json` liefert String) → Passkey-Login/-Registrierung defekt | Kritisch | Behoben |
| 2 | Leerer Bearer-Header bei fehlendem Cloudflare-Token → `LocalProtocolError`/500 | Mittel | Behoben (Header nur bei gesetztem Token + `httpx.HTTPError`-Catch) |
| 3 | Webhook-URL (inkl. Secret) konnte in Fehlerlogs landen | Hoch | Behoben (nur Fehlertyp wird geloggt) |
| 4 | XSS über Cloudflare-/Benutzereingaben (Security-Feed, Passkey-Namen, Zone-Werte) | Hoch | Behoben (Escaping im Frontend + Jinja2-Autoescape) |
| 5 | CSRF: zustandsverändernde Requests ohne Origin-Prüfung | Mittel | Behoben (Origin-Middleware; durch Bearer-Token ohnehin geringes Risiko) |
| 6 | Kein Cache-Schutz für authentifizierten Inhalt | Mittel | Behoben (`Cache-Control: no-store`, `HTTP_CACHE_NO_STORE`) |
| 7 | Fehlende Security-Header (Clickjacking, MIME-Sniffing, CSP) | Mittel | Behoben (CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`) |
| 8 | Docker-Container lief als root | Hoch | Behoben (non-root UID 1001) |
| 9 | Abhängigkeiten mit bekannten CVEs (fastapi/starlette/jinja2/python-dotenv/python-multipart) | Hoch | Behoben (Upgrade, `pip-audit`: 0 Findings) |
| 10 | Session-Cookie als Auth-Persistenz | Mittel | Entfernt (stateless Token, kein Cookie) |

## 3. Schutzmaßnahmen im Betrieb (getestet)

- **Rate-Limiting** auf Login-/Admin-Endpunkten (`RATE_LIMIT_*`) – in-memory,
  setzt daher **genau einen Uvicorn-Worker** voraus (Standard, siehe Dockerfile).
- **CSRF-/Origin-Check** für POST/PUT/PATCH/DELETE (zusätzliche Verteidigungsebene).
- **Feature-Gates & Config-Guards:** Quick Actions / Action Center sind ohne
  konfigurierte Cloudflare-Zugangsdaten deaktiviert; jede Aktion prüft zusätzlich serverseitig.
- **Datenbankzugriffe ausschließlich über SQLAlchemy-ORM** (kein String-SQL → keine SQL-Injection).
- **Keine Secrets im Repo:** `.env` ist gitignored; `SECRET`-Defaults werden beim Start
  gewarnt (`SESSION_SECRET_KEY`-Warnung im Log).
- **Security-Header:** CSP (`default-src 'self'`, keine externen Origins), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (`SECURITY_HEADERS_ENABLED`).
- **Abhängigkeiten gepinnt** und via `pip-audit` geprüft (Stand Audit: 0 bekannte Schwachstellen).

## 4. Restrisiken & Empfehlungen

1. **Token im `sessionStorage`:** Ein erfolgreicher XSS-Angriff kann den Token auslesen.
   Gegenmaßnahmen sind implementiert (Escaping, CSP ohne externe Origins, no-store).
   Zusätzlich empfohlen: Dashboard nur über HTTPS ausliefern (Reverse-Proxy mit SSL
   wird dringend empfohlen; zusätzlich HSTS am Proxy aktivieren).
2. **PIN-Authentifizierung:** Der Nutzer wählt die PIN selbst – 4-stellige PINs sind
   brute-force-anfällig. Für kritische Infrastruktur 6+ Stellen und `AUTH_MODE=passkey`
   (nur Hardware-Token) bevorzugen.
3. **In-memory State (Rate-Limiter, Lockout, WebAuthn-Challenges):** gilt pro Prozess.
   Bei mehr als einem Worker würde das Rate-Limiting umgangen – **nur 1 Worker betreiben**
   (Default im Dockerfile). Eine Redis-/DB-basierte Variante wäre der nächste Ausbauschritt.
4. **Docker-Volume:** Der Container läuft als UID 1001; das Host-Verzeichnis `./data`
   muss einmalig `chown -R 1001:1001 data/` erhalten (Hinweis in docker-compose.yml).
5. **Host-Header:** Uvicorn validiert den Host-Header nicht (kein Trusted-Host-Filter).
   Die WebAuthn-Origin-Prüfung verhindert Passkey-Angriffe; für den Zugriff aus dem
   Internet dennoch empfehlenswert, einen Reverse-Proxy mit eigenem Host-Whitelisting davorzuschalten.
6. **Rate-Limiting per IP:** Bei Zugriff über einen Reverse-Proxy ohne
   `X-Forwarded-For`-Weiterleitung sehen alle Anfragen wie eine IP aus (Lockout-Wirkung
   begrenzt). Proxy entsprechend konfigurieren (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`).
7. **`AUTH_MODE=none`** existiert bewusst nur für isolierte interne Netze – nicht ins Internet exponieren.

## 5. Deployment-Checkliste (kritische Infrastruktur)

- [ ] `SESSION_SECRET_KEY` auf zufälligen Wert (`python3 -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] `AUTH_MODE=pin|passkey|both` (nie `none` außerhalb isolierter Netze)
- [ ] `AUTH_PIN_LENGTH=6`+ bzw. `WEBAUTHN_USER_VERIFICATION=required` bei Passkeys
- [ ] `ADMIN_TOKEN` gesetzt (Passkey-Verwaltung)
- [ ] `WEBAUTHN_RP_ID`/`WEBAUTHN_ORIGIN` exakt auf die aufrufende Domain/URL gesetzt
- [ ] TLS über Reverse-Proxy, HSTS am Proxy
- [ ] `chown -R 1001:1001 data/` (non-root Container)
- [ ] Nicht mehr als 1 Uvicorn-Worker
- [ ] `docker compose up -d --build` und Login-Flow (PIN + Passkey) einmal durchspielen
