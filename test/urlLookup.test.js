const assert = require('node:assert/strict');
const test = require('node:test');
const { lookupUrl } = require('../src/urlLookup');

const publicAddress = { address: '93.184.216.34', family: 4 };

function optionsForResponse(statusCode, location) {
  return {
    resolveImpl: async () => [publicAddress],
    requestImpl: async () => ({ statusCode, location }),
  };
}

test('reports a reachable URL and confirms that its domain resolves', async () => {
  const result = await lookupUrl('https://example.com/page', optionsForResponse(200));

  assert.equal(result.status, 'reachable');
  assert.equal(result.domainExists, true);
  assert.equal(result.httpStatus, 200);
  assert.match(result.detail, /reachability only, not safety/i);
  assert.doesNotMatch(result.detail, /HTTP \d{3}/i);
});

test('reports missing pages and missing domains as not found', async () => {
  const missingPage = await lookupUrl('https://example.com/missing', optionsForResponse(404));
  const missingDomain = await lookupUrl('https://no-such-domain.example', {
    resolveImpl: async () => { throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' }); },
  });

  assert.equal(missingPage.status, 'not_found');
  assert.equal(missingPage.domainExists, true);
  assert.equal(missingPage.httpStatus, 404);
  assert.doesNotMatch(missingPage.detail, /HTTP \d{3}/i);
  assert.equal(missingDomain.status, 'not_found');
  assert.equal(missingDomain.domainExists, false);
  assert.equal(missingDomain.httpStatus, null);
});

test('follows redirects and resolves the redirected hostname again', async () => {
  const requestedHosts = [];
  const result = await lookupUrl('https://example.com/start', {
    resolveImpl: async (hostname) => {
      requestedHosts.push(hostname);
      return [publicAddress];
    },
    requestImpl: async (url) => url.pathname === '/start'
      ? { statusCode: 302, location: 'https://other.example/final' }
      : { statusCode: 200 },
  });

  assert.equal(result.status, 'reachable');
  assert.deepEqual(requestedHosts, ['example.com', 'other.example']);
});

test('does not request private, local, non-standard-port, or credentialed destinations', async () => {
  let requestSent = false;
  const options = {
    resolveImpl: async () => [{ address: '127.0.0.1', family: 4 }],
    requestImpl: async () => {
      requestSent = true;
      return { statusCode: 200 };
    },
  };
  const privateAddress = await lookupUrl('https://example.com', options);
  const localAddress = await lookupUrl('http://localhost');
  const nonStandardPort = await lookupUrl('https://example.com:8443');
  const embeddedCredentials = await lookupUrl('https://user:pass@example.com');

  assert.equal(privateAddress.status, 'unavailable');
  assert.equal(localAddress.status, 'unavailable');
  assert.equal(nonStandardPort.status, 'unavailable');
  assert.equal(embeddedCredentials.status, 'unavailable');
  assert.equal(requestSent, false);
});

test('blocks a redirect to a private address before making the redirected request', async () => {
  const requests = [];
  const result = await lookupUrl('https://example.com/start', {
    resolveImpl: async (hostname) => hostname === 'example.com'
      ? [publicAddress]
      : [{ address: '::ffff:7f00:1', family: 6 }],
    requestImpl: async () => {
      requests.push('requested');
      return { statusCode: 302, location: 'https://internal.example/' };
    },
  });

  assert.equal(result.status, 'unavailable');
  assert.equal(requests.length, 1);
});

test('returns unavailable when a destination times out or responds with a server error', async () => {
  const timedOut = await lookupUrl('https://example.com', {
    resolveImpl: async () => [publicAddress],
    requestImpl: async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }); },
  });
  const serverError = await lookupUrl('https://example.com', optionsForResponse(503));

  assert.equal(timedOut.status, 'unavailable');
  assert.equal(serverError.status, 'unavailable');
  assert.equal(serverError.domainExists, true);
  assert.equal(serverError.httpStatus, 503);
});

test('bounds slow DNS lookups', async () => {
  const result = await lookupUrl('https://example.com', {
    resolveImpl: async () => new Promise(() => {}),
    timeoutMs: 5,
  });

  assert.equal(result.status, 'unavailable');
  assert.match(result.detail, /timed out/i);
});

test('uses a ranged GET only when the server does not support HEAD', async () => {
  const methods = [];
  const result = await lookupUrl('https://example.com', {
    resolveImpl: async () => [publicAddress],
    requestImpl: async (_url, _addresses, method) => {
      methods.push(method);
      return { statusCode: method === 'HEAD' ? 405 : 200 };
    },
  });

  assert.equal(result.status, 'reachable');
  assert.deepEqual(methods, ['HEAD', 'GET']);
});
