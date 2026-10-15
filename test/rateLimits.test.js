const assert = require('node:assert/strict');
const express = require('express');
const test = require('node:test');
const { createRateLimiters } = require('../src/rateLimits');

test('returns 429 after the configured API request limit and includes standard headers', async (context) => {
  const app = express();
  const { api } = createRateLimiters({
    RATE_LIMIT_WINDOW_MS: '60000',
    API_RATE_LIMIT_MAX: '1',
  });
  app.use('/api', api);
  app.get('/api/test', (_request, response) => response.json({ ok: true }));

  const server = app.listen(0, '127.0.0.1');
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  await new Promise((resolve) => server.once('listening', resolve));

  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/api/test`;
  const firstResponse = await fetch(url);
  const limitedResponse = await fetch(url);

  assert.equal(firstResponse.status, 200);
  assert.equal(limitedResponse.status, 429);
  assert.deepEqual(await limitedResponse.json(), {
    code: 'RATE_LIMITED',
    scope: 'api',
    limit: 1,
    windowMs: 60000,
    error: 'Too many API requests. Please try again later.',
  });
  assert.ok(limitedResponse.headers.has('ratelimit'));
  assert.ok(limitedResponse.headers.has('retry-after'));
});

test('allows five APK uploads per 15 minutes and identifies that limit in the 429 response', async (context) => {
  const app = express();
  const { apkUpload } = createRateLimiters({
    APK_UPLOAD_RATE_LIMIT_MAX: '5',
    APK_UPLOAD_RATE_LIMIT_WINDOW_MS: '900000',
  });
  app.post('/upload', apkUpload, (_request, response) => response.sendStatus(204));

  const server = app.listen(0, '127.0.0.1');
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  await new Promise((resolve) => server.once('listening', resolve));

  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/upload`;
  const responses = [];
  for (let index = 0; index < 6; index += 1) {
    responses.push(await fetch(url, { method: 'POST' }));
  }

  assert.deepEqual(responses.map(({ status }) => status), [204, 204, 204, 204, 204, 429]);
  assert.deepEqual(await responses[5].json(), {
    code: 'RATE_LIMITED',
    scope: 'apk_upload',
    limit: 5,
    windowMs: 900000,
    error: 'Too many APK uploads. Please try again later.',
  });
});