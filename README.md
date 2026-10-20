# CyberRakshak backend

Node.js API for the mobile app's focused cyber-safety chat and preliminary scan checks.

## Setup

```powershell
cd backend
npm install
Copy-Item .env.example .env
```

Set `GROQ_API_KEY` and `GROQ_MODEL` in `backend/.env`. The key stays on this server and is never bundled into the app.

Start the API:

```powershell
npm run dev
```

The Android emulator reaches the host machine through `http://10.0.2.2:8000`. Set the app's `API_BASE_URL` to that address. A physical device should use the computer's LAN IP instead. For a release APK, use the deployed Render HTTPS URL instead.

## API rate limits

The API applies IP-based limits before request-body parsing: 300 API requests, 20 chat requests, 30 translations, and 60 scans per 15 minutes by default. APK multipart uploads are limited to 5 per 15 minutes. Configure these with the `*_RATE_LIMIT_*` values in `.env`; `Retry-After` and standard `RateLimit` response headers are returned when a limit is exceeded. These are initial per-IP defaults and should be reviewed using real traffic and load tests. Shared mobile/carrier IPs can cause multiple users to share a limit.

The default rate-limit store is in memory and works only within one backend process. It resets on restart and does not coordinate multiple instances. For multi-instance production, use a shared rate-limit store or enforce equivalent quotas at the trusted edge (for example AWS WAF/API Gateway), and retain application limits for expensive operations. Set `TRUST_PROXY_HOPS` only to the number of proxy hops that are actually trusted; the Render Blueprint sets it to one for Render's ingress.

## Render deployment

The repository root contains `render.yaml`. Create a Render Blueprint from the repository, then set `GROQ_API_KEY` as a secret on the service. Render runs `npm install` from this directory and starts the API with `npm start`; `PORT` is supplied by Render. Use `/health` as the service health check.

## API documentation

The OpenAPI 3 specification is in `openapi.yaml`. With the backend running locally, open `http://localhost:8000/api-docs` for Swagger UI or `http://localhost:8000/api-docs.json` for the JSON document. Update the `servers` URL in `openapi.yaml` to your deployed HTTPS URL when using Swagger UI against staging or production. The documentation endpoints are public; restrict access at the hosting layer if they should not be exposed.

## Endpoints

- `GET /health`
- `GET /api/contacts` returns the contacts shown on the app's Locator screen.
- `GET /api/quiz?type=link|email|sms|phone|file&language=en|hi|pa` returns ten random story questions from that scam type's 100-question inventory. Each question includes its localized story and answer choices; the correct answer is withheld.
- `POST /api/quiz/answer` with `{ "type": "link", "questionId": "link-1-1", "answerIndex": 0, "language": "hi" }` checks one answer and returns whether it was correct, the localized correct choice, and an explanation.
- `POST /api/chat` with `{ "message": "...", "session_id": "..." }`
- `POST /api/scan` with `{ "url": "..." }`
- `POST /api/scan` with `{ "type": "email|mobile", "value": "..." }` or `{ "type": "sms", "header": "..." }`
- `POST /api/scan` multipart with a `file` field (maximum 150 MB). APK responses include the declared Android `permissions` list.

File uploads have no application-level request timeout so slow connections can finish. APK manifests are read from the APK ZIP archive and their Android binary XML is decoded in Node.js; no Python runtime or temporary files are required. Email domain checks query MX records on each request, falling back to address records for domains without MX records. DNS proves only that a domain has mail/address records; it cannot authenticate the sender.

URL scans calculate the risk score, recommendation, and explanation from deterministic URL-pattern checks; no AI provider is called for URL assessment. A live lookup result of not found (missing public DNS record or HTTP 404/410) raises the score to at least 80/100 and marks the result suspicious. This is a high-risk signal, not proof of maliciousness; other inconclusive lookup failures do not trigger this score override. The separate live lookup uses built-in Node.js DNS and HTTP modules (no paid service or added dependency), is bounded to five seconds, sends `HEAD` requests, uses a one-byte ranged `GET` only when `HEAD` is unsupported, and follows at most five redirects. It refuses private/local addresses, embedded URL credentials, and non-standard ports; it does not download page content or check threat reputation. The 0-100 risk estimate is heuristic, not a calibrated probability. Shorteners are flagged because they conceal destinations, while free-hosting domains are context only and are not treated as malicious by themselves.

Chat scope is checked locally against cyber-awareness terms and context. Multiple spelling errors in a recognized English cybersecurity keyword may be tolerated when the intended keyword is sufficiently similar and unambiguous; the original message is passed to the chat model unchanged.

The SMS scan analyzes only the supplied header using `data/sms.json` and `data/sms_header.json`. It accepts `XY - ABCDEF - M`, `ABCDEF - M`, and `ABCDEF` (spaces around separators are optional), where the optional category is `S` (Service), `P` (Promotional), `T` (Transactional), or `G` (Government). When `XY` is present, its first character is looked up as the TSP and its second as the LSA. The actual header is matched against the `header` field and its `name` is shown as the Principal Entity Name. These offline files cannot confirm current TRAI/DLT registration, sender identity, route, or registered-template compliance; no SMS message content is submitted or analyzed. See the [TRAI/PIB release on header and template misuse](https://www.pib.gov.in/PressReleasePage.aspx?PRID=1899849), [reverification of registered headers/templates](https://pib.gov.in/PressReleasePage.aspx?PRID=1927160), and [commercial SMS traceability](https://pib.gov.in/PressReleasePage.aspx?PRID=2086103). Report unwanted commercial communication using TRAI's DND channels, including 1909, as described in the [DoT/PIB 2026 update](https://pib.gov.in/PressReleasePage.aspx?PRID=2223950&reg=3&lang=1).

The mobile-number check uses offline numbering metadata to assess Indian country, number validity, line type, and obvious placeholder patterns. It cannot confirm that a number is active, reachable, owned by a person, currently assigned to a carrier, or a physical SIM rather than a forwarded/virtual service. Those checks require an appropriately consented carrier or phone-intelligence provider; a valid numbering range is not proof of legitimacy.
