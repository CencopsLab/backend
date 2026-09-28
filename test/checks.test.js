const assert = require('node:assert/strict');
const test = require('node:test');
const { checkFile, checkUrl, parseSmsHeader, runTextCheck } = require('../src/checks');
const { reviewUrlWithGroq } = require('../src/urlAssessment');

function mockGroqResponse(score, reason) {
  return async (_url, options) => {
    assert.match(options.headers.Authorization, /^Bearer /);
    return {
      ok: true,
      json: async () => ({
        choices: [{ message: { content: JSON.stringify({ risk_score: score, reason }) } }],
      }),
    };
  };
}

test('adds a validated Groq review for a URL with no visible warning signals', async () => {
  const result = await reviewUrlWithGroq('https://example.com', {
    apiKey: 'test-key',
    model: 'test-model',
    fetchImpl: mockGroqResponse(12, 'No obvious deceptive pattern appears in the URL.'),
  });

  assert.equal(result.urlAssessment.status, 'available');
  assert.equal(result.urlAssessment.riskScore, 12);
  assert.equal(result.urlAssessment.recommendation, 'no_obvious_risk');
  assert.match(result.summary, /not confirmation that the site is safe/);
});

test('deterministic URL warning signals prevent a low Groq score from minimizing risk', async () => {
  const result = await reviewUrlWithGroq('http://bit.ly/urgent', {
    apiKey: 'test-key',
    model: 'test-model',
    fetchImpl: mockGroqResponse(8, 'The short link obscures its destination.'),
  });

  assert.equal(result.urlAssessment.riskScore, 70);
  assert.equal(result.urlAssessment.recommendation, 'avoid');
  assert.equal(result.verdict, 'suspicious');
});

test('returns a deterministic result when Groq is not configured', async () => {
  let requestSent = false;
  const result = await reviewUrlWithGroq('https://example.com', {
    apiKey: '',
    model: 'test-model',
    fetchImpl: async () => { requestSent = true; },
  });

  assert.equal(requestSent, false);
  assert.equal(result.urlAssessment.status, 'unavailable');
  assert.equal(result.checks.find((check) => check.name === 'HTTPS connection').status, 'pass');
});

test('returns assessable URL signals for secure and suspicious addresses', () => {
  const secure = checkUrl('https://example.com');
  const suspicious = checkUrl('http://192.0.2.1/verify');

  assert.deepEqual(secure.checks.map((check) => check.status), ['pass', 'pass', 'pass', 'pass', 'pass']);
  assert.equal(suspicious.checks.filter((check) => check.status === 'warning').length, 3);
});

test('treats URL shorteners as concealment signals and free hosting as context only', () => {
  const shortener = checkUrl('https://bit.ly/a1b2');
  const hosted = checkUrl('https://login-example.vercel.app');

  assert.equal(shortener.checks.find((check) => check.name === 'URL shortener').status, 'warning');
  assert.equal(hosted.checks.find((check) => check.name === 'Free-hosting platform').status, 'info');
});

test('marks an APK with no readable Android manifest as suspicious', async () => {
  const result = await checkFile(
    { originalname: 'missing-manifest.apk', buffer: Buffer.alloc(0) },
    { inspectApkPermissions: async () => { throw new Error('Could not read AndroidManifest.xml: missing'); } },
  );

  assert.equal(result.verdict, 'suspicious');
  assert.equal(result.checks[0].status, 'warning');
  assert.match(result.summary, /cannot be verified/);
});

test('keeps APK tool failures unrelated to the manifest as unknown', async () => {
  const result = await checkFile(
    { originalname: 'tool-error.apk', buffer: Buffer.alloc(0) },
    { inspectApkPermissions: async () => { throw new Error('Python runtime unavailable'); } },
  );

  assert.equal(result.verdict, 'unknown');
  assert.equal(result.checks[0].status, 'unavailable');
});

test('marks an email as legitimate-looking when its domain resolves', async () => {
  const result = await runTextCheck('email', 'abc123@xyz.com', { lookup: async () => ({ address: '93.184.216.34', family: 4 }) });

  assert.equal(result.verdict, 'safe');
  assert.equal(result.guidance.findings[0], 'The sender domain xyz.com has address records.');
  assert.equal(result.checks.find((check) => check.name === 'Sender domain').status, 'pass');
});

test('checks the mail exchanger on every email request', async () => {
  let mxLookups = 0;
  const options = { mxLookup: async () => { mxLookups += 1; return [{ exchange: 'mail.xyz.com', priority: 10 }]; } };

  await runTextCheck('email', 'first@xyz.com', options);
  await runTextCheck('email', 'second@xyz.com', options);

  assert.equal(mxLookups, 2);
});

test('falls back to address records when a domain has no MX records', async () => {
  let addressLookups = 0;
  const result = await runTextCheck('email', 'abc123@example.com', {
    mxLookup: async () => [],
    addressLookup: async () => { addressLookups += 1; return { address: '192.0.2.1', family: 4 }; },
  });

  assert.equal(result.verdict, 'safe');
  assert.equal(addressLookups, 1);
});

test('reports transient DNS failure as unavailable instead of a bad domain', async () => {
  const result = await runTextCheck('email', 'abc123@example.com', {
    mxLookup: async () => { throw Object.assign(new Error('Temporary DNS failure'), { code: 'EAI_AGAIN' }); },
    lookup: async () => { throw Object.assign(new Error('Temporary DNS failure'), { code: 'EAI_AGAIN' }); },
  });

  assert.equal(result.verdict, 'unknown');
  assert.equal(result.checks.find((check) => check.name === 'Sender domain').status, 'unavailable');
  assert.match(result.summary, /could not be checked right now/);
});

test('marks an email as suspicious when its domain does not resolve', async () => {
  const result = await runTextCheck('email', 'abc123@not-real.invalid', { lookup: async () => { throw Object.assign(new Error('Not found'), { code: 'ENOTFOUND' }); } });

  assert.equal(result.verdict, 'suspicious');
  assert.match(result.summary, /sender domain not-real\.invalid could not be found/);
  assert.equal(result.checks.find((check) => check.name === 'Sender domain').status, 'warning');
});

test('accepts an Indian mobile numbering range without claiming legitimacy', () => {
  const result = runTextCheck('mobile', '+91 98765-43210');

  assert.equal(result.verdict, 'unknown');
  assert.equal(result.normalizedNumber, '+919876543210');
  assert.equal(result.checks.find((check) => check.name === 'Country').status, 'pass');
  assert.equal(result.checks.find((check) => check.name === 'Line type').status, 'pass');
  assert.equal(result.checks.find((check) => check.name === 'Reachability / ownership').status, 'unavailable');
});

test('flags a valid number from outside India', () => {
  const result = runTextCheck('mobile', '+1 415 555 2671');

  assert.equal(result.verdict, 'suspicious');
  assert.match(result.summary, /not belong to the Indian numbering region/);
});

test('does not treat an Indian landline as a mobile', () => {
  const result = runTextCheck('mobile', '1234567890');

  assert.equal(result.verdict, 'suspicious');
  assert.match(result.summary, /not classified as mobile/);
});

test('rejects malformed input and reports unavailable live checks', () => {
  const result = runTextCheck('mobile', 'abc123');

  assert.equal(result.verdict, 'suspicious');
  assert.equal(result.checks[0].name, 'Number format');
  assert.equal(result.checks[1].status, 'unavailable');
});

test('parses TSP, LSA, header, and category with optional separator spaces', () => {
  const parsed = parseSmsHeader('AA- IOCXRP -G');

  assert.equal(parsed.tspCode, 'A');
  assert.equal(parsed.lsaCode, 'A');
  assert.equal(parsed.header, 'IOCXRP');
  assert.equal(parsed.categoryCode, 'G');
});

test('looks up provider, service area, principal entity, and category', () => {
  const result = runTextCheck('sms', 'AA - IOCXRP - S');

  assert.equal(result.verdict, 'safe');
  assert.equal(result.scannedTarget, 'AA - IOCXRP - S');
  assert.equal(result.headerDetails.serviceProvider, 'Bharti Airtel Ltd/ Bharti Hexacom Ltd');
  assert.equal(result.headerDetails.serviceArea, 'Andhra Pradesh');
  assert.equal(result.headerDetails.header, 'IOCXRP');
  assert.equal(result.headerDetails.principalEntityName, 'iNDIAN OIL CORPORATION LIMITED');
  assert.equal(result.headerDetails.category, 'Service');
  assert.equal(result.checks.find((check) => check.name === 'Principal Entity directory').status, 'pass');
  assert.equal(result.checks.find((check) => check.name === 'Live TRAI / DLT registration and route').status, 'unavailable');
});

test('looks up a header and suffix without attempting TSP or LSA resolution', () => {
  const result = runTextCheck('sms', 'IOCXRP - G');

  assert.equal(result.verdict, 'likely_safe');
  assert.equal(result.headerDetails.serviceProvider, null);
  assert.equal(result.headerDetails.serviceArea, null);
  assert.equal(result.headerDetails.principalEntityName, 'iNDIAN OIL CORPORATION LIMITED');
  assert.equal(result.headerDetails.category, 'Government');
  assert.equal(result.checks.some((check) => check.name === 'Service Provider / TSP'), false);
  assert.equal(result.checks.some((check) => check.name === 'Service Area / LSA'), false);
});

test('looks up a header without resolving absent optional components', () => {
  const result = runTextCheck('sms', 'IOCXRP');

  assert.equal(result.verdict, 'likely_safe');
  assert.equal(result.headerDetails.header, 'IOCXRP');
  assert.equal(result.headerDetails.principalEntityName, 'iNDIAN OIL CORPORATION LIMITED');
  assert.equal(result.headerDetails.category, null);
  assert.equal(result.checks.find((check) => check.name === 'Header category').status, 'unavailable');
  assert.equal(result.checks.find((check) => check.name === 'Registered message template').status, 'unavailable');
});

test('maps each permitted SMS category suffix', () => {
  const categories = { S: 'Service', P: 'Promotional', T: 'Transactional', G: 'Government' };

  for (const [suffix, category] of Object.entries(categories)) {
    const result = runTextCheck('sms', `IOCXRP - ${suffix}`);
    assert.equal(result.headerDetails.category, category);
  }
});

test('marks an SMS header absent from the supplied directory as suspicious', () => {
  const result = runTextCheck('sms', 'UNKNOWN - G');

  assert.equal(result.verdict, 'suspicious');
  assert.match(result.summary, /does not prove fraud/);
});