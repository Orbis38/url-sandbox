# UrlProbe UI refresh — design source

Source files of the UI refresh mockups the web interface in `website/templates/` is built from.

- Live canvas: https://claude.ai/artifact/FDhiUNFPXhT5vE3vzpY7SP (private until shared from its Share menu)
- `canvas.json` — artboard index (positions, titles)
- `*.dc.html` — one file per screen:

| File | Screen | Implemented in |
| --- | --- | --- |
| `Main.dc.html` | New Analysis | `website/templates/upload.html` |
| `Queue.dc.html` | Task Queue | `queue.html`, `queue_rows.html`, `static/queue.js` |
| `Report.dc.html` | Analysis Report (has an "Edge cases" tweak: 20 redirects, long URLs, failed task) | `report.html`, `static/report.js` |
| `ApiKeys.dc.html` | API Keys | `api_keys.html` |
| `Logs.dc.html` | Active Logs | `activelogs.html`, `static/activelogs.js` |
| `Login.dc.html` | Sign in / Register | `admin/index.html` |
| `Error.dc.html` | Error page | `error.html` |
| `Foundations.dc.html` | Tokens, type scale, status pills, controls | `:root` tokens and components in `base.html` |

The `.dc.html` files are Design Component sources: they need the canvas runtime (`support.js`) to render, so open them from the canvas link above rather than directly in a browser. Data shown in them (URLs, task IDs, keys) is sample data.

Known gap: the mockup's redirect chain ("How it got there") needs per-hop data the sandbox does not record yet — today only the final URL and a `redirected` flag are stored, which is what the report shows.
