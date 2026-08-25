# FlareHub

Schlankes Cloudflare Analytics & Quick Actions Dashboard für Unraid/Docker.

- FastAPI-Backend + Jinja2-Templates + Plain JS/CSS (keine SPA)
- PIN- und/oder Passkey/WebAuthn-Login (via `.env` steuerbar)
- Analytics-Collector holt alle X Minuten GraphQL-Metriken von Cloudflare
- Chart.js-Zeitreihen für Requests & Bandbreite
- Security-Feed (WAF/Firewall-Events)
- Quick Actions: Dev Mode, Purge Cache, Under Attack Mode

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

## Konfiguration

Alle Einstellungen laufen über die `.env` — siehe `.env.example` für die vollständige,
kommentierte Liste (Auth, Session, Cloudflare, Collector, Feature-Toggles, Benachrichtigungen,
Rate-Limiting).

## Struktur

```
flarehub/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
└── app/
    ├── main.py         # FastAPI-Routen
    ├── auth.py         # PIN + WebAuthn/Passkey-Logik
    ├── collector.py     # Cloudflare GraphQL-Collector & Zone-Actions
    ├── config.py        # .env-Settings
    ├── database.py       # SQLAlchemy-Modelle
    ├── templates/
    │   ├── login.html
    │   └── dashboard.html
    └── static/
        ├── styles.css
        └── webauthn.js
```
