// require('dotenv/config');
require('dotenv').config({
  path: '/home/ubuntu/cyber_rakshak_be/backend/src/.env'
});
const cors = require('cors');
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const multer = require('multer');
const swaggerUi = require('swagger-ui-express');
const basicAuth = require('express-basic-auth');
const YAML = require('yaml');
const { SYSTEM_PROMPT } = require('./prompt');
const { requestChatReply, translateChatReply, translateScanTexts, translateScanResult } = require('./chatCompletion');
const { greetingReply, incompleteAnswerReply, isCyberRelated, isGreeting, outOfScopeReply } = require('./chatScope');
const { checkFile, runTextCheck } = require('./checks');
const { applyLookupPriority, assessUrl } = require('./urlAssessment');
const { lookupUrl } = require('./urlLookup');
const { createRateLimiters } = require('./rateLimits');
const { SCAM_TYPES, checkAnswer, sampleQuestions } = require('./quiz');
const { TRANSLATIONS: QUIZ_TRANSLATIONS } = require('./quizTranslations');
const contacts = require('../data/contacts.json');

const app = express();
const openApiDocument = YAML.parse(
  fs.readFileSync(path.join(__dirname, '..', 'openapi.yaml'), 'utf8'),
);
const port = Number(process.env.PORT || 8000);
const requestTimeoutMs = Number(process.env.REQUEST_TIMEOUT_MS || 0);
const maxTokens = Number(process.env.GROQ_MAX_TOKENS || 768);
const temperature = Number(process.env.GROQ_TEMPERATURE || 0.2);
const groqModel = String(process.env.GROQ_MODEL || '').trim();
const sessions = new Map();
const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS || 0);
if (!Number.isSafeInteger(trustProxyHops) || trustProxyHops < 0) {
  throw new Error('TRUST_PROXY_HOPS must be a non-negative integer');
}
const rateLimiters = createRateLimiters();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 150 * 1024 * 1024 },
});

const allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map((origin) => origin.trim());
app.use(cors({ origin: allowedOrigins.includes('*') ? true : allowedOrigins }));
app.set('trust proxy', trustProxyHops);
app.get('/api-docs.json', (_request, response) => {
  response.json(openApiDocument);
});
app.use('/api-docs', basicAuth({
    users: { 'cyberadmin': 'CyberAdmin101' },
    challenge: true, // Prompts the browser for a login dialog
  }),swaggerUi.serve, swaggerUi.setup(openApiDocument));
app.use('/api', rateLimiters.api);
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_request, response) => {
  response.json({ ok: true, service: 'cyber-sahayak-backend' });
});

app.get('/api/contacts', (_request, response) => {
  response.json(contacts);
});

app.get('/api/quiz', rateLimiters.scan, (request, response) => {
  const type = typeof request.query.type === 'string' ? request.query.type : '';
  const language = ['en', 'hi', 'pa'].includes(request.query.language) ? request.query.language : 'en';
  const questions = sampleQuestions(type, language);
  if (!questions) {
    return response.status(400).json({ error: `type must be one of: ${Object.keys(SCAM_TYPES).join(', ')}` });
  }
  return response.json({
    type,
    label: QUIZ_TRANSLATIONS[language]?.[type]?.label || SCAM_TYPES[type].label,
    questionCount: questions.length,
    questions,
  });
});

app.post('/api/quiz/answer', rateLimiters.scan, (request, response) => {
  const { type, questionId, answerIndex } = request.body || {};
  if (typeof type !== 'string' || !Object.hasOwn(SCAM_TYPES, type)) {
    return response.status(400).json({ error: `type must be one of: ${Object.keys(SCAM_TYPES).join(', ')}` });
  }
  if (typeof questionId !== 'string' || !Number.isSafeInteger(answerIndex) || answerIndex < 0 || answerIndex > 3) {
    return response.status(400).json({ error: 'Provide a questionId and an answerIndex from 0 to 3' });
  }
  const language = ['en', 'hi', 'pa'].includes(request.body.language) ? request.body.language : 'en';
  const result = checkAnswer(type, questionId, answerIndex, language);
  if (!result) return response.status(404).json({ error: 'Quiz question not found for this scam type' });
  return response.json(result);
});

app.post('/api/chat', rateLimiters.chat, async (request, response) => {
  const message = typeof request.body?.message === 'string' ? request.body.message.trim() : '';
  const sessionId = typeof request.body?.session_id === 'string' ? request.body.session_id : 'anonymous';
  const language = ['en', 'hi', 'pa'].includes(request.body?.language) ? request.body.language : 'en';
  const languageName = { en: 'English', hi: 'Hindi', pa: 'Punjabi' }[language];

  if (!message || message.length > 2000) {
    return response.status(400).json({ error: 'message must be between 1 and 2000 characters' });
  }

  if (isGreeting(message)) {
    return response.json({ reply: greetingReply(language) });
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
    if (error.code === 'INCOMPLETE_CHAT_RESPONSE') {
      const reply = incompleteAnswerReply(message, language);
      sessions.set(sessionId, [...history, { role: 'user', content: message }, { role: 'assistant', content: reply }].slice(-10));
      return response.json({ reply });
    }
    console.error('Chat request failed:', error.message);
    return response.status(502).json({ error: 'Unable to generate a complete response right now. Please try again or ask a more focused question.' });
  }
});

app.post('/api/chat/translate', rateLimiters.translate, async (request, response) => {
  const text = typeof request.body?.text === 'string' ? request.body.text.trim() : '';
  const language = ['en', 'hi', 'pa'].includes(request.body?.language) ? request.body.language : null;
  if (!text || text.length > 10000 || !language) {
    return response.status(400).json({ error: 'Provide chat text (maximum 10000 characters) and a supported language' });
  }
  if (!process.env.GROQ_API_KEY || !groqModel) {
    return response.status(503).json({ error: 'Chat translation is not configured on the backend' });
  }
  try {
    const translation = await translateChatReply({
      apiKey: process.env.GROQ_API_KEY,
      model: groqModel,
      text,
      language,
    });
    return response.json({ translation });
  } catch (error) {
    console.error('Chat translation failed:', error.message);
    return response.status(502).json({ error: 'Unable to translate the previous reply right now.' });
  }
});

app.post('/api/scan/translate', rateLimiters.translate, async (request, response) => {
  const { entries } = request.body || {};
  const language = ['en', 'hi', 'pa'].includes(request.body?.language) ? request.body.language : null;
  if (
    !language
    || !Array.isArray(entries)
    || entries.length < 1
    || entries.length > 40
    || entries.some((entry) => (
      !entry
      || typeof entry.id !== 'string'
      || !/^[a-z][a-z0-9_]{0,63}$/.test(entry.id)
      || typeof entry.text !== 'string'
      || !entry.text.trim()
      || entry.text.length > 2000
    ))
    || new Set(entries.map((entry) => entry.id)).size !== entries.length
    || entries.reduce((total, entry) => total + entry.text.length, 0) > 12000
  ) {
    return response.status(400).json({ error: 'Provide 1-40 unique scan text entries and a supported target language (en, hi, or pa)' });
  }
  if (!process.env.GROQ_API_KEY || !groqModel) {
    return response.status(503).json({ error: 'Scan translation is not configured on the backend' });
  }
  try {
    const translations = await translateScanTexts({
      apiKey: process.env.GROQ_API_KEY,
      model: groqModel,
      entries,
      language,
    });
    return response.json({ translations });
  } catch (error) {
    console.error('Scan translation failed:', error.message);
    return response.status(502).json({ error: 'Unable to translate scan analysis right now.' });
  }
});

app.post('/api/scan', rateLimiters.scan, (request, response, next) => {
  if (/^multipart\/form-data\b/i.test(request.get('content-type') || '')) {
    return rateLimiters.apkUpload(request, response, next);
  }
  return next();
}, upload.single('file'), (request, response, next) => {
  if (request.body?.language === 'hi' || request.body?.language === 'pa') {
    return rateLimiters.translate(request, response, next);
  }
  return next();
}, async (request, response) => {
  const requestedLanguage = request.body?.language;
  if (requestedLanguage !== undefined && !['en', 'hi', 'pa'].includes(requestedLanguage)) {
    return response.status(400).json({ error: 'language must be one of: en, hi, pa' });
  }
  const language = requestedLanguage || 'en';
  const sendScanResult = async (result) => {
    if (language === 'en') return response.json({ ...result, language });
    if (!process.env.GROQ_API_KEY || !groqModel) {
      return response.status(503).json({ error: 'Scan translation is not configured on the backend' });
    }
    try {
      const translated = await translateScanResult({
        apiKey: process.env.GROQ_API_KEY,
        model: groqModel,
        result,
        language,
      });
      return response.json({ ...translated, language });
    } catch (error) {
      console.error('Scan result translation failed:', error.message);
      return response.status(502).json({ error: 'Unable to translate scan results right now.' });
    }
  };

  if (request.file) return sendScanResult(await checkFile(request.file));

  const type = typeof request.body?.type === 'string' ? request.body.type : '';
  const value = typeof request.body?.value === 'string' ? request.body.value.trim() : '';
  const header = typeof request.body?.header === 'string' ? request.body.header.trim() : '';
  const url = typeof request.body?.url === 'string' ? request.body.url.trim() : '';

  if (url) {
    if (url.length > 2048) return response.status(400).json({ error: 'URL must be 2048 characters or fewer' });
    const [urlAssessment, urlLookup] = await Promise.all([
      assessUrl(url),
      lookupUrl(url),
    ]);
    const assessment = applyLookupPriority(urlAssessment, urlLookup);
    return sendScanResult({
      ...assessment,
      summary: `${assessment.summary} ${urlLookup.detail}`,
      urlLookup,
    });
  }
  if (type === 'sms') {
    if (!header || header.length > 64) {
      return response.status(400).json({ error: 'Provide an SMS header (maximum 64 characters)' });
    }
    return sendScanResult(runTextCheck(type, header));
  }
  if (type && value && value.length <= 10000) {
    const result = await runTextCheck(type, value);
    if (result) return sendScanResult(result);
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
  console.log(`Cyber Sahayak backend listening on http://0.0.0.0:${port}`);
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
