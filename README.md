# VoiceAI

KI-gestützter Sprachassistent mit Helpdesk-Modus, Nutzer- und Rollenverwaltung.

## Voraussetzungen

- Docker + Docker Compose
- Anthropic API-Key und/oder Mistral API-Key

## Einrichten

```bash
cp .env.example .env
# .env öffnen und alle Werte befüllen (insbesondere ADMIN_PIN ändern!)
```

## Starten

```bash
docker compose up -d
```

App ist erreichbar unter `http://localhost:5010` (bzw. `APP_URL`).

## Umgebungsvariablen

| Variable | Beschreibung |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API-Key für Claude |
| `MISTRAL_API_KEY` | API-Key für Mistral |
| `SECRET_KEY` | Flask Session Secret (zufällig, lang) |
| `ADMIN_PIN` | PIN für Admin-Bereich — **vor erstem Start ändern!** |
| `APP_URL` | Öffentliche URL der App (z.B. `https://meinserver.duckdns.org/voiceai`) |
| `SMTP_HOST` | SMTP-Server für E-Mail-Versand |
| `SMTP_PORT` | SMTP-Port (Standard: 587) |
| `SMTP_USER` | SMTP-Benutzer |
| `SMTP_PASS` | SMTP-Passwort / App-Passwort |
| `REPOS_BASE` | Pfad zu den Repositories im Container (Standard: `/repos`) |
| `USERS_FILE` | Pfad zur Benutzerdatei (Standard: `/data/users.json`) |

## Rollen

- **user** — nur Chat
- **developer** — Chat + Agent-Modus (Repo-Zugriff)
- **admin** — alles inkl. Developer-Zugriff auf alle Repos
