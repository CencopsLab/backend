const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const YAML = require('yaml');

const specification = YAML.parse(
  fs.readFileSync(path.join(__dirname, '..', 'openapi.yaml'), 'utf8'),
);

test('OpenAPI document describes the backend routes', () => {
  assert.equal(specification.openapi, '3.0.3');
  assert.deepEqual(Object.keys(specification.paths), [
    '/health',
    '/api/contacts',
    '/api/quiz',
    '/api/quiz/answer',
    '/api/chat',
    '/api/chat/translate',
    '/api/scan/translate',
    '/api/scan',
  ]);
  assert.ok(specification.paths['/api/scan'].post.requestBody.content['multipart/form-data']);
  assert.ok(specification.paths['/api/scan'].post.requestBody.content['application/json']);
  assert.deepEqual(
    specification.paths['/api/scan'].post.requestBody.content['application/json'].schema.oneOf
      .map((schema) => schema.$ref.split('/').at(-1))
      .map((schemaName) => specification.components.schemas[schemaName].properties.language.$ref),
    Array(3).fill('#/components/schemas/Language'),
  );
  assert.deepEqual(
    specification.paths['/api/scan/translate'].post.requestBody.content['application/json'].schema.properties.language.enum,
    ['en', 'hi', 'pa'],
  );
});
