const assert = require('node:assert/strict');
const test = require('node:test');
const { requestChatReply } = require('../src/chatCompletion');

function mockResponse(content, finishReason) {
  return {
    ok: true,
    json: async () => ({
      choices: [{ message: { content }, finish_reason: finishReason }],
    }),
  };
}

test('uses one request for a complete answer', async () => {
  const requests = [];
  const reply = await requestChatReply({
    apiKey: 'test-key',
    model: 'test-model',
    messages: [{ role: 'user', content: 'How do I respond to a scam?' }],
    temperature: 0.2,
    maxTokens: 768,
    fetchImpl: async (_url, options) => {
      requests.push(JSON.parse(options.body));
      return mockResponse('Do not share codes. Contact your bank using its official number.', 'stop');
    },
  });

  assert.equal(reply, 'Do not share codes. Contact your bank using its official number.');
  assert.equal(requests.length, 1);
  assert.equal(requests[0].max_tokens, 768);
});

test('rewrites a truncated answer instead of continuing its partial text', async () => {
  const requests = [];
  const responses = [
    mockResponse('Partial text that must not be returned', 'length'),
    mockResponse('A concise, complete response.', 'stop'),
  ];
  const reply = await requestChatReply({
    apiKey: 'test-key',
    model: 'test-model',
    messages: [{ role: 'user', content: 'Explain phishing and how to stay safe.' }],
    temperature: 0.2,
    maxTokens: 768,
    fetchImpl: async (_url, options) => {
      requests.push(JSON.parse(options.body));
      return responses.shift();
    },
  });

  assert.equal(reply, 'A concise, complete response.');
  assert.equal(requests.length, 2);
  assert.match(requests[1].messages.at(-1).content, /Rewrite the original answer as a concise, complete response/);
  assert.doesNotMatch(JSON.stringify(requests[1].messages), /Partial text that must not be returned/);
});

test('rewrites a Markdown table for a compact mobile answer even when generation stops normally', async () => {
  const requests = [];
  const responses = [
    mockResponse('| Step | Advice |\n| --- | --- |\n| 1 | Use a unique password |', 'stop'),
    mockResponse('- Use a unique password for every account.\n- Turn on MFA.', 'stop'),
  ];
  const reply = await requestChatReply({
    apiKey: 'test-key',
    model: 'test-model',
    messages: [{ role: 'user', content: 'How do I secure my accounts?' }],
    temperature: 0.2,
    maxTokens: 768,
    fetchImpl: async (_url, options) => {
      requests.push(JSON.parse(options.body));
      return responses.shift();
    },
  });

  assert.equal(reply, '- Use a unique password for every account.\n- Turn on MFA.');
  assert.equal(requests.length, 2);
  assert.match(requests[1].messages.at(-1).content, /3-5 short bullet points, not a table/);
});

test('does not return an answer if the concise rewrite is still truncated', async () => {
  let requestCount = 0;
  await assert.rejects(
    requestChatReply({
      apiKey: 'test-key',
      model: 'test-model',
      messages: [{ role: 'user', content: 'Explain this threat in detail.' }],
      temperature: 0.2,
      maxTokens: 768,
      fetchImpl: async () => {
        requestCount += 1;
        return mockResponse('An incomplete answer', 'length');
      },
    }),
    /rewrite still exceeded/,
  );
  assert.equal(requestCount, 2);
});