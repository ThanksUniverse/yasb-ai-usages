# AI Usage Dashboard

A minimal, local dashboard for tracking your AI service usage across ChatGPT, Copilot, Claude, Ollama, Z.AI, and Gemini in real-time.

## Features

- **Unified view** of all AI service usage from a single dashboard
- **Individual refresh** per service with independent loading states
- **Only shows configured services** in the overview
- **YASB widget integration** with interactive installer wizard
- **Zero dependencies** beyond Express (no database, no build step)
- **Privacy-first**: runs locally, never sends your data anywhere

## Supported services

| Service | Auth Method | What it tracks |
| --- | --- | --- |
| ChatGPT | Access token | Session/weekly rate limits, credits |
| Copilot | GitHub PAT | Premium request quota, chat/completion limits |
| Claude | Session cookie | 5h/7d usage windows, per-model breakdown |
| Gemini | Google Cloud auth + project ID | Per-model RPM/TPM/RPD limits and 24h peak usage |
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
| `GEMINI_PROJECT_ID` | Google Cloud project ID for Gemini quotas |
| `GEMINI_ACCESS_TOKEN` | Optional Google OAuth access token fallback |
| `BIND_HOST` | Network binding (default `127.0.0.1`) |
| `PORT` | HTTP port (default `3456`) |

Gemini is read from Google Cloud's official Service Usage and Monitoring APIs. The easiest setup is local `gcloud` auth:

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

## YASB Widget Integration

Show your AI usage directly in your [YASB](https://github.com/amnweb/yasb) status bar — each service gets its own color-coded widget with real-time updates.

### Quick Setup (Recommended)

The dashboard includes a built-in YASB widget installer:

1. Start the dashboard: `npm start`
2. Open `http://localhost:3456` in your browser
3. Click **YASB Widgets** in the top-right corner
4. Click **Detect YASB Installation** — it will find your YASB config automatically
5. Select the AI services you want to display
6. Choose a layout:
   - **Grouped** (recommended) — collapsible container with individual service widgets
   - **Single Widget** — one compact line showing all services
7. Click **Install to YASB**
8. Add the widget name to your bar's widget list:

```yaml
# In your YASB config.yaml, find your bar's widgets and add:
widgets_right: ["ai_usage_group", "volume", "clock"]
```

YASB will auto-reload the new widgets if `watch_config: true` is enabled.

### Manual Setup

If you prefer to set things up manually, or the auto-installer can't find your config:

**1. Copy widget definitions** from `yasb-widgets/config.yaml` into your YASB `config.yaml`:

```yaml
# Add under your widgets section:
  ai_usage_group:
    type: "yasb.grouper.GrouperWidget"
    options:
      class_name: "ai-usage-group"
      widgets: ["ai_chatgpt", "ai_copilot", "ai_claude", "ai_ollama", "ai_zai", "ai_gemini", "ai_status"]

  ai_chatgpt:
    type: "yasb.custom.CustomWidget"
    options:
      label: "<span>󰒫</span> {data[chatgpt_session]}%"
      # ... (see yasb-widgets/config.yaml for full definitions)
```

**2. Copy styles** from `yasb-widgets/styles.css` into your YASB `styles.css`:

```css
.ai-usage-group { margin: 0 4px; padding: 0 6px; border-radius: 4px; background: rgba(255,255,255,0.03); }
.ai-chatgpt { color: #10b981; }
.ai-copilot { color: #58a6ff; }
/* ... (see yasb-widgets/styles.css for full styles) */
```

**3. Add to your bar:**

```yaml
widgets_right: ["ai_usage_group", "volume", "clock"]
```

### How It Works

- Each service polls its own endpoint (`/api/yasb/{service}`) every 120 seconds
- Unconfigured services return HTTP 204 → YASB's `hide_empty: true` auto-hides them
- The status widget (`ai_status`) polls `/api/health` every 5 seconds and shows countdown to next data refresh
- **Left-click** a widget to toggle compact/detailed view
- **Right-click** any widget to force-refresh all data
- **Left-click** the status dot to open the full dashboard

### Widget Colors

| Service | Color |
| --- | --- |
| ChatGPT | 🟢 Green `#10b981` |
| Copilot | 🔵 Blue `#58a6ff` |
| Claude | 🟠 Orange `#e09145` |
| Ollama | 🟣 Purple `#a78bfa` |
| Z.AI | 🔷 Blue `#4f8cff` |
| Gemini | 🔵 Google Blue `#4285f4` |
| Status | 🟢 Green `#22c55e` |

Usage above 70% shows amber warning, above 85% shows red with pulse animation.

### Troubleshooting

| Problem | Solution |
| --- | --- |
| Widgets not showing | Ensure the server is running (`npm start`) and check `http://localhost:3456/api/health` |
| All widgets disappear at once | The server uses stale-while-revalidate caching — widgets should never all disappear. If they do, restart the server. |
| Specific service missing | Check that the service is configured in Settings. Unconfigured services auto-hide. |
| Wrong port | If using a non-default port, the installer auto-adjusts the curl URLs. For manual setup, replace `3456` in all widget configs. |
| YASB not auto-reloading | Enable `watch_config: true` in your YASB bar config, or restart YASB manually. |

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
| `/api/yasb/detect` | `GET` | Detect YASB installation and installed widgets |
| `/api/yasb/preview` | `GET` | Preview widget config/styles for selected services |
| `/api/yasb/install` | `POST` | Install widgets into YASB config (admin only) |
| `/api/yasb/uninstall` | `POST` | Remove AI widgets from YASB config (admin only) |
| `/api/chatgpt/usage` | `GET` | ChatGPT rate limits and credits |
| `/api/copilot/usage` | `GET` | Copilot plan and quota data |
| `/api/claude/usage` | `GET` | Claude usage windows |
| `/api/ollama/usage` | `GET` | Ollama cloud/local usage |
| `/api/zai/usage` | `GET` | Z.AI quota and usage data |
| `/api/gemini/usage` | `GET` | Gemini per-model rate limits and recent usage |

## Development

```bash
npm run dev  # Runs with --watch for auto-reload
```

## License

MIT
