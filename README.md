# FlareHub

Schlankes Cloudflare Analytics & Quick Actions Dashboard für Unraid/Docker.

- FastAPI-Backend + Jinja2-Templates + Plain JS/CSS (keine SPA)
- PIN- und/oder Passkey/WebAuthn-Login (via `.env` steuerbar)
- Admin-Token-geschützte Passkey-Verwaltung (hinzufügen/löschen) getrennt vom normalen Login
- Analytics-Collector holt alle X Minuten GraphQL-Metriken von Cloudflare (`httpRequests1mGroups`)
- Zeitraum-Auswahl (6h/24h/7T/30T/90T/1J) mit automatischer Auflösung
- Charts: Requests, Bandbreite, Cache-Ratio, Threats (Chart.js)
- Security-Feed (WAF/Firewall-Events)
- Quick Actions: Dev Mode, Purge Cache, Under Attack Mode
- Mehrstufige Datenaggregation (Rohdaten → Stunden → Tage), damit die DB dauerhaft klein bleibt
- Collector-Diagnose (letzter Lauf, Fehler, Speicherstatistik) auf der Einstellungsseite

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
└── app/
    ├── main.py         # FastAPI-Routen
    ├── auth.py         # PIN + WebAuthn/Passkey-Logik + Admin-Token-Gate
    ├── collector.py     # Cloudflare GraphQL-Collector & Zone-Actions
    ├── config.py        # .env-Settings
    ├── database.py       # SQLAlchemy-Modelle + Rollup-/Aggregationslogik
    ├── templates/
    │   ├── login.html
    │   ├── dashboard.html
    │   └── settings.html
    └── static/
        ├── styles.css
        └── webauthn.js
```

