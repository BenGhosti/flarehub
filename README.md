# FlareHub

Schlankes Cloudflare Analytics & Quick Actions Dashboard für Unraid/Docker.

- FastAPI-Backend + Jinja2-Templates + Plain JS/CSS (keine SPA)
- **Stateless Auth ohne Cookies:** PIN-/Passkey-Login stellt ein kurzlebiges Token aus
  (nur im `sessionStorage` des Browsers) – jeder neue Besuch erfordert einen erneuten Login
- PIN- und/oder Passkey/WebAuthn-Login (via `.env` steuerbar)
- Admin-Token-geschützte Passkey-Verwaltung (hinzufügen/löschen) getrennt vom normalen Login
- Analytics-Collector holt alle X Minuten GraphQL-Metriken von Cloudflare (`httpRequests1mGroups`)
- Zeitraum-Auswahl (6h/24h/7T/30T/90T/1J) mit automatischer Auflösung
- Charts: Requests, Bandbreite, Cache-Ratio, Cached vs. Uncached, Unique Visitors,
  Page Views, Threats (Chart.js, lokal ausgeliefert – kein CDN)
- Pie-Charts: Cache-Aufteilung (Cached/Uncached) und Threat-Aktionen (block/challenge/...)
- Security-Feed (WAF/Firewall-Events)
- Quick Actions: Dev Mode, Purge Cache, Under Attack Mode
- **Action Center** (`/actions`): Cache-Purge für bestimmte URLs, Collector manuell starten,
  read-only Zone-Status-Übersicht
- Mehrstufige Datenaggregation (Rohdaten → Stunden → Tage), damit die DB dauerhaft klein bleibt
- Collector-Diagnose (letzter Lauf, Fehler, Speicherstatistik) auf der Einstellungsseite
- Security-Hardening: Security-Header (CSP etc.), non-root Docker, PIN-Lockout, Rate-Limiting,
  `pip-audit`-geprüfte Abhängigkeiten – siehe [SECURITY.md](SECURITY.md)

## Setup

1. `.env.example` nach `.env` kopieren und anpassen:
   ```bash
   cp .env.example .env
   ```

2. Cloudflare-Zugangsdaten eintragen (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`).
   Der API-Token benötigt die Berechtigungen:
   - Zone → Analytics → Read
   - Zone → Cache Purge → Edit
   - Zone → Zone Settings → Edit

3. Auth-Modus wählen (`AUTH_MODE=pin|passkey|both|none`).

   Für PIN-Login einen Hash erzeugen:
   ```bash
   python3 -c "import bcrypt; print(bcrypt.hashpw(b'DEINE_PIN', bcrypt.gensalt()).decode())"
   ```
   Ergebnis in `AUTH_PIN_HASH` eintragen.

   Für Passkey-Login `WEBAUTHN_RP_ID` und `WEBAUTHN_ORIGIN` auf die tatsächliche Domain/URL setzen.

4. `SESSION_SECRET_KEY` auf einen langen zufälligen String setzen:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

5. Starten:
   ```bash
   docker compose up -d --build
   ```

6. `ADMIN_TOKEN` setzen (langer, zufälliger Wert), um die Passkey-Verwaltung freizuschalten:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(24))"
   ```

7. Dashboard unter `http://<host>:8000` aufrufen und mit PIN einloggen. Unter
   **Einstellungen → Passkey-Verwaltung entsperren** das Admin-Token eingeben (10 Minuten
   gültig) und dort Passkeys hinzufügen oder löschen. Das Admin-Token ist eine zusätzliche
   Hürde getrennt vom normalen Login — auch mit aktiver Session ist ohne korrektes Token
   keine Passkey-Verwaltung möglich.

## Sicherheit

- **Keine Session-Cookies:** nach PIN-/Passkey-Login wird ein kurzlebiges, signiertes
  Token ausgestellt, das nur im `sessionStorage` des Browsers lebt und als
  `Authorization: Bearer`-Header mitgesendet wird. Beim Schließen des Browsers ist es
  weg – **jeder neue Besuch erfordert einen erneuten PIN-/Passkey-Login**
  (`SESSION_EXPIRY_HOURS` = oberes Limit, Standard 4 h).
- **Admin-Token-Grant:** 10 Minuten gültig, nur im `sessionStorage` (`X-Admin-Grant`-Header),
  nie auf der Platte. Passkey-Verwaltung ist damit doppelt geschützt.
- **PIN-Lockout:** nach `AUTH_PIN_MAX_ATTEMPTS` Fehlversuchen je IP für
  `AUTH_PIN_LOCKOUT_SECONDS` Sekunden gesperrt; zusätzlich Rate-Limiting auf Login-Endpunkte.
- **CSRF:** alle zustandsverändernden Requests werden per Origin-Check auf Same-Origin geprüft.
- **Security-Header:** CSP (nur eigene Ressourcen), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (`SECURITY_HEADERS_ENABLED`).
- **Kein Browser-Caching:** Seiten & APIs bekommen `Cache-Control: no-store` (`HTTP_CACHE_NO_STORE`).
- **XSS:** alle Cloudflare-/Benutzereingaben werden escaped (Frontend + Jinja2-Autoescape).
- **Docker läuft non-root** (UID 1001, einmalig `chown -R 1001:1001 data/`).
- **Abhängigkeiten gepinnt + `pip-audit`-geprüft** (0 bekannte Schwachstellen).
- Details: siehe [SECURITY.md](SECURITY.md) (vollständiges Audit, Restrisiken, Checkliste).

## Konfiguration

Alle Einstellungen laufen über die `.env` — siehe `.env.example` für die vollständige,
kommentierte Liste (Auth, Session, Cloudflare, Collector, Datenaufbewahrung, Feature-Toggles,
Benachrichtigungen, Rate-Limiting).

## Datenhaltung

Die Analytics-Daten durchlaufen eine dreistufige Aggregation, damit die SQLite-Datenbank
auch nach Jahren im Betrieb klein bleibt, ohne den Langzeit-Trend zu verlieren:

| Stufe | Auflösung | Aufbewahrung (Default) | .env-Variable |
|---|---|---|---|
| Rohdaten | 10 Min. (`COLLECTOR_INTERVAL_MINUTES`) | 48 Std. | `RAW_RETENTION_HOURS` |
| Stunden-Rollup | 1 Std. | 30 Tage | `HOURLY_RETENTION_DAYS` |
| Tages-Rollup | 1 Tag | 730 Tage (~2 Jahre) | `DATA_RETENTION_DAYS` |

Die Verdichtung läuft automatisch nach jedem Collector-Durchlauf. Die Zeitraum-Auswahl im
Dashboard wählt automatisch die passende Stufe (z.B. nutzt "1 Jahr" die Tages-Rollups statt
Millionen Rohdatenpunkte abzufragen). Auf der Einstellungsseite zeigt der Bereich
**System & Datenspeicher** die aktuelle Zeilenzahl je Stufe sowie den Status des letzten
Collector-Laufs (inkl. Fehlermeldung, falls z.B. das Cloudflare-Token ungültig ist).

## Test-Server (UI-Preview ohne Cloudflare)

Auf Windows (auch direkt vom NAS-Laufwerk) startet `test-webserver.bat` einen
Dummy-Server, um die komplette UI (Login, Dashboard, Charts, Security-Feed,
Einstellungen) ohne echte Cloudflare-Zugangsdaten zu begutachten:

```bat
test-webserver.bat          :: Standard-Port 8000
test-webserver.bat 8080     :: eigener Port
```

- Login: **PIN 1234**
- Admin-Token (Einstellungen → Passkey-Verwaltung): **test-admin-token**
- Legt automatisch eine lokale Python-Umgebung an (`%LOCALAPPDATA%\FlareHub\venv`)
  und installiert die Abhängigkeiten beim ersten Start.
- Befüllt `data/test.db` über `scripts/seed_demo_data.py` mit realistischen
  Beispieldaten (alle Zeiträume 6h–1J, 50 Security-Events).
- Öffnet den Browser automatisch; Beenden mit `Ctrl+C` im Konsolenfenster.

## Cloudflare API – Hinweise

- Genutzter GraphQL-Node: `httpRequests1mGroups` (Zone-scope, 10-Minuten-Rohwerte für
  Requests, Cache-Hits, Bandbreite, Threats, Page Views, Unique Visitors).
- Firewall-Events über `firewallEventsAdaptive`.
- Cloudflare-Limits, die der Collector beachtet: GraphQL-Rate-Limit von Cloudflare-Seite (Standard
  300 Queries/5 Min.), max. 10.000 Records pro Antwort (wir fragen deutlich konservativer ab,
  siehe `COLLECTOR_MAX_RECORDS_PER_QUERY`), sowie 401/403/429-Antworten werden erkannt und im
  Collector-Log verständlich protokolliert statt nur einen generischen Fehler zu werfen.
- Free-Plan-Nutzer haben eingeschränkten historischen Zugriff auf manche Datasets (z.B. Firewall-
  Events nur 14 Tage zurück) – das ist eine Cloudflare-Plan-Limitierung, keine FlareHub-Einschränkung.

## Struktur

```
flarehub/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── SECURITY.md         # Security-Audit (Modell, Befunde, Restrisiken, Checkliste)
├── test-webserver.bat  # Windows-Testserver mit Demo-Daten (PIN 1234)
└── app/
    ├── main.py         # FastAPI-Routen
    ├── auth.py         # Stateless Token-Auth + PIN + WebAuthn + Admin-Token-Gate
    ├── collector.py    # Cloudflare GraphQL-Collector & Zone-Actions
    ├── config.py       # .env-Settings
    ├── database.py     # SQLAlchemy-Modelle + Rollup-/Aggregationslogik
    ├── templates/
    │   ├── login.html
    │   ├── dashboard.html
    │   ├── actions.html
    │   └── settings.html
    └── static/
        ├── styles.css
        ├── auth.js     # Stateless Auth-Helfer (sessionStorage + Bearer-Header)
        ├── webauthn.js
        └── vendor/chart.umd.min.js  # Chart.js lokal (offline-fähig)
```

