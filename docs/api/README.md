# Offline API UI

This folder contains a static, offline Swagger UI that loads the local OpenAPI spec.

Files you should vendor into `docs/api/ui/`:

- `swagger-ui.css`
- `swagger-ui-bundle.js`
- `swagger-ui-standalone-preset.js` (optional)
- `openapi.json` (copied from `docs/api/openapi.json` or the repo root `openapi.json`)

How to vendor the files (example steps):

1. Download the latest Swagger UI distribution from the official project releases (vendor the UMD bundle and CSS). Example release files you need:
   - `swagger-ui-bundle.js`
   - `swagger-ui-standalone-preset.js` (optional, provides try-it-out UI)
   - `swagger-ui.css`

2. Place the files into `docs/api/ui/` alongside `index.html`.

3. Copy or symlink the OpenAPI spec into the same folder as `openapi.json` (or leave it in `docs/api/openapi.json` — the index.html will search nearby paths).

Open the UI:

- Double-click `docs/api/ui/index.html` to open in your default browser.
- Or open the file URL, for example:

  file:///path/to/repo/docs/api/ui/index.html

Notes and requirements:

- No network required. Do not point `index.html` at remote URLs.
- Do not vendor remote JS/CSS at runtime — only include local files.
- This is intentionally static so the docs remain an auditable artifact.

If you want me to vendor specific Swagger UI files into this repo, tell me which version to fetch and I will add them (manual copy only; I cannot access the network without your approval).