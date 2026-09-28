require('dotenv/config');

const cors = require('cors');
const express = require('express');
const multer = require('multer');
const { SYSTEM_PROMPT } = require('./prompt');
const { requestChatReply } = require('./chatCompletion');
const { isCyberRelated, outOfScopeReply } = require('./chatScope');
const { checkFile, runTextCheck } = require('./checks');
const { reviewUrlWithGroq } = require('./urlAssessment');
const contacts = require('../data/contacts.json');

const app = express();
const port = Number(process.env.PORT || 8000);
const requestTimeoutMs = Number(process.env.REQUEST_TIMEOUT_MS || 0);
const maxTokens = Number(process.env.GROQ_MAX_TOKENS || 768);
const temperature = Number(process.env.GROQ_TEMPERATURE || 0.2);
const groqModel = String(process.env.GROQ_MODEL || '').trim();
const sessions = new Map();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 150 * 1024 * 1024 },
});

const allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map((origin) => origin.trim());
app.use(cors({ origin: allowedOrigins.includes('*') ? true : allowedOrigins }));
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_request, response) => {
  response.json({ ok: true, service: 'CyberRakshak-backend' });
});

app.get('/api/contacts', (_request, response) => {
  response.json(contacts);
});

app.post('/api/chat', async (request, response) => {
  const message = typeof request.body?.message === 'string' ? request.body.message.trim() : '';
  const sessionId = typeof request.body?.session_id === 'string' ? request.body.session_id : 'anonymous';
  const language = ['en', 'hi', 'pa'].includes(request.body?.language) ? request.body.language : 'en';
  const languageName = { en: 'English', hi: 'Hindi', pa: 'Punjabi' }[language];

  if (!message || message.length > 2000) {
    return response.status(400).json({ error: 'message must be between 1 and 2000 characters' });
  }

  const history = sessions.get(sessionId) || [];
  if (!isCyberRelated(message, history)) {
    return response.json({ reply: outOfScopeReply(language) });
  }

  if (!process.env.GROQ_API_KEY) {
    return response.status(503).json({ error: 'GROQ_API_KEY is not configured on the backend' });
  }
  if (!groqModel) {
    return response.status(503).json({ error: 'GROQ_MODEL is not configured on the backend' });
  }

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'system', content: `Reply entirely in ${languageName}. This language requirement is mandatory for every sentence, heading, and bullet. Keep only technical names, URLs, permission names, and emergency number 1930 unchanged when needed.` },
    ...history,
    { role: 'user', content: message },
  ];

  try {
    const reply = await requestChatReply({
      apiKey: process.env.GROQ_API_KEY,
      model: groqModel,
      messages,
      temperature,
      maxTokens,
    });

    sessions.set(sessionId, [...history, { role: 'user', content: message }, { role: 'assistant', content: reply }].slice(-10));
    return response.json({ reply });
  } catch (error) {
    console.error('Chat request failed:', error.message);
    return response.status(502).json({ error: 'Unable to generate a complete response right now. Please try again or ask a more focused question.' });
  }
});

app.post('/api/scan', upload.single('file'), async (request, response) => {
  if (request.file) return response.json(await checkFile(request.file));

  const type = typeof request.body?.type === 'string' ? request.body.type : '';
  const value = typeof request.body?.value === 'string' ? request.body.value.trim() : '';
  const header = typeof request.body?.header === 'string' ? request.body.header.trim() : '';
  const url = typeof request.body?.url === 'string' ? request.body.url.trim() : '';

  if (url) {
    if (url.length > 2048) return response.status(400).json({ error: 'URL must be 2048 characters or fewer' });
    return response.json(await reviewUrlWithGroq(url));
  }
  if (type === 'sms') {
    if (!header || header.length > 64) {
      return response.status(400).json({ error: 'Provide an SMS header (maximum 64 characters)' });
    }
    return response.json(runTextCheck(type, header));
  }
  if (type && value && value.length <= 10000) {
    const result = await runTextCheck(type, value);
    if (result) return response.json(result);
  }

  return response.status(400).json({ error: 'Provide a URL, file, or supported text check' });
});

app.use((error, _request, response, _next) => {
  if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
    return response.status(413).json({ error: 'File is too large. Maximum size is 150 MB.' });
  }
  console.error('Unhandled request error:', error.message);
  return response.status(500).json({ error: 'Unexpected backend error' });
});

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`CyberRakshak backend listening on http://0.0.0.0:${port}`);
});
server.timeout = requestTimeoutMs;
server.requestTimeout = requestTimeoutMs;

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${port} is already in use. Stop the existing backend process or change PORT in backend/.env.`);
    process.exitCode = 1;
    return;
  }
  console.error('Backend could not start:', error.message);
  process.exitCode = 1;
});
