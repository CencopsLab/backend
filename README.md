# CyberSaathi backend

Node.js API for the mobile app's focused cyber-safety chat and preliminary scan checks.

## Setup

```powershell
cd backend
npm install
Copy-Item .env.example .env
```

Set `GROQ_API_KEY` and `GROQ_MODEL` in `backend/.env`. The key stays on this server and is never bundled into the app.

APK manifest inspection requires Python 3 on the backend machine. Set `PYTHON_BIN` in `backend/.env` if the executable is not available as `python`.

Start the API:

```powershell
npm run dev
```

The Android emulator reaches the host machine through `http://10.0.2.2:8000`. Set the app's `API_BASE_URL` to that address. A physical device should use the computer's LAN IP instead. For a release APK, use the deployed Render HTTPS URL instead.

## Render deployment

The repository root contains `render.yaml`. Create a Render Blueprint from the repository, then set `GROQ_API_KEY` as a secret on the service. Render runs `npm install` from this directory and starts the API with `npm start`; `PORT` is supplied by Render. Use `/health` as the service health check.

## Endpoints

- `GET /health`
- `POST /api/chat` with `{ "message": "...", "session_id": "..." }`
- `POST /api/scan` with `{ "url": "..." }`
- `POST /api/scan` with `{ "type": "email|mobile", "value": "..." }` or `{ "type": "sms", "header": "..." }`
- `POST /api/scan` multipart with a `file` field. APK responses include the declared Android `permissions` list.

URL scans combine local URL-pattern checks with a Groq AI review of the URL string. The model does not browse the site, follow redirects, or check live domain reputation. Its 0-100 risk estimate is heuristic, not a calibrated probability; deterministic URL warnings impose a minimum score. Shorteners are flagged because they conceal destinations, while free-hosting domains are context only and are not treated as malicious by themselves. If Groq is unavailable, the API returns the deterministic checks and marks the AI review unavailable.

The SMS scan analyzes only the supplied header using `data/sms.json` and `data/sms_header.json`. It accepts `XY - ABCDEF - M`, `ABCDEF - M`, and `ABCDEF` (spaces around separators are optional), where the optional category is `S` (Service), `P` (Promotional), `T` (Transactional), or `G` (Government). When `XY` is present, its first character is looked up as the TSP and its second as the LSA. The actual header is matched against the `header` field and its `name` is shown as the Principal Entity Name. These offline files cannot confirm current TRAI/DLT registration, sender identity, route, or registered-template compliance; no SMS message content is submitted or analyzed. See the [TRAI/PIB release on header and template misuse](https://www.pib.gov.in/PressReleasePage.aspx?PRID=1899849), [reverification of registered headers/templates](https://pib.gov.in/PressReleasePage.aspx?PRID=1927160), and [commercial SMS traceability](https://pib.gov.in/PressReleasePage.aspx?PRID=2086103). Report unwanted commercial communication using TRAI's DND channels, including 1909, as described in the [DoT/PIB 2026 update](https://pib.gov.in/PressReleasePage.aspx?PRID=2223950&reg=3&lang=1).

The mobile-number check uses offline numbering metadata to assess Indian country, number validity, line type, and obvious placeholder patterns. It cannot confirm that a number is active, reachable, owned by a person, currently assigned to a carrier, or a physical SIM rather than a forwarded/virtual service. Those checks require an appropriately consented carrier or phone-intelligence provider; a valid numbering range is not proof of legitimacy.
