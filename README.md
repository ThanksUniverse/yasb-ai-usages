# AI Usage Dashboard

A minimal, local dashboard for tracking your AI service usage across ChatGPT, Copilot, Claude, Ollama, and Z.AI in real-time.

## Features

- **Unified view** of all AI service usage from a single dashboard
- **Individual refresh** per service with independent loading states
- **Only shows configured services** in the overview
- **YASB widget integration** via summary API endpoint
- **Zero dependencies** beyond Express (no database, no build step)
- **Privacy-first**: runs locally, never sends your data anywhere

## Supported services

| Service | Auth Method | What it tracks |
| --- | --- | --- |
| ChatGPT | Access token | Session/weekly rate limits, credits |
| Copilot | GitHub PAT | Premium request quota, chat/completion limits |
| Claude | Session cookie | 5h/7d usage windows, per-model breakdown |
| Ollama | API key + optional cookie | Cloud usage percentages, local model status |
| Z.AI | Auth token | Token/MCP quotas, model and tool usage |

## Quick start

```bash
npm install
cp .env.example .env
# Fill in only the credentials you use
npm start
```

Open `http://127.0.0.1:3456`

## Configuration

All configuration is read from `.env` and environment variables. Only fill in what you use.

| Variable | Purpose |
| --- | --- |
| `CHATGPT_ACCESS_TOKEN` | ChatGPT usage API auth |
| `GITHUB_TOKEN` | Copilot usage API auth (PAT with `read:user` scope) |
| `CLAUDE_SESSION_KEY` | Claude session cookie value |
| `OLLAMA_API_KEY` | Ollama cloud API key |
| `OLLAMA_LOCAL_HOST` | Local Ollama host (default `http://localhost:11434`) |
| `OLLAMA_SESSION_COOKIE` | Enables real Ollama usage % scraping |
| `ZAI_AUTH_TOKEN` | Z.AI API auth token |
| `BIND_HOST` | Network binding (default `127.0.0.1`) |
| `PORT` | HTTP port (default `3456`) |

## Security

This project is designed for **local, private usage**.

- Binds to `127.0.0.1` by default (loopback only)
- Security headers on all responses (CSP, X-Frame-Options, etc.)
- JSON body size limited to 32KB
- Write endpoints require loopback + origin verification or admin token
- Timing-safe token comparison to prevent timing attacks
- `.env` written with mode `0o600` (owner-only read/write)
- No secrets in source code; `.env` and `data/` are git-ignored

## API endpoints

| Endpoint | Method | Description |
| --- | --- | --- |
| `/api/config` | `GET` | Provider configuration status (no secrets) |
| `/api/config` | `POST` | Update configuration (admin only) |
| `/api/platforms` | `GET` | Platform metadata |
| `/api/yasb/summary` | `GET` | Flattened summary for YASB widgets |
| `/api/chatgpt/usage` | `GET` | ChatGPT rate limits and credits |
| `/api/copilot/usage` | `GET` | Copilot plan and quota data |
| `/api/claude/usage` | `GET` | Claude usage windows |
| `/api/ollama/usage` | `GET` | Ollama cloud/local usage |
| `/api/zai/usage` | `GET` | Z.AI quota and usage data |

## YASB integration

Point your YASB custom widget to poll `http://localhost:3456/api/yasb/summary` every 120 seconds.

- Widget config example: `yasb-widgets/config.yaml`
- Widget styles: `yasb-widgets/styles.css`

## Development

```bash
npm run dev  # Runs with --watch for auto-reload
```

## License

MIT
