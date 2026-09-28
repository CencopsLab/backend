const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const REWRITE_PROMPT = 'Rewrite the original answer as a concise, complete response for a mobile chat. Use 3-5 short bullet points, not a table or code block. Summarize broad topics, include essential safety steps and caveats, keep the original language, and end naturally.';

function containsMarkdownTable(content) {
  const lines = content.split(/\r?\n/);
  const separator = /^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$/;
  return lines.some((line, index) => line.includes('|') && separator.test(lines[index + 1] || ''));
}

async function requestChatReply({
  apiKey,
  model,
  messages,
  temperature,
  maxTokens,
  fetchImpl = fetch,
}) {
  async function complete(requestMessages) {
    const response = await fetchImpl(GROQ_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        messages: requestMessages,
        temperature,
        max_tokens: maxTokens,
      }),
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload?.error?.message || `Groq request failed (${response.status})`);
    }

    const choice = payload?.choices?.[0];
    const content = choice?.message?.content;
    if (typeof content !== 'string' || !content.trim()) {
      throw new Error('The language model returned an empty response');
    }

    return { content, finishReason: choice.finish_reason };
  }

  const firstResult = await complete(messages);
  const needsRewrite = firstResult.finishReason === 'length' || containsMarkdownTable(firstResult.content);
  if (!needsRewrite) return firstResult.content.trim();

  const lastMessage = messages.at(-1);
  const rewriteMessages = lastMessage?.role === 'user'
    ? [
        ...messages.slice(0, -1),
        { ...lastMessage, content: `${lastMessage.content}\n\n${REWRITE_PROMPT}` },
      ]
    : [...messages, { role: 'user', content: REWRITE_PROMPT }];
  const rewriteResult = await complete(rewriteMessages);

  if (rewriteResult.finishReason === 'length') {
    throw new Error('The concise rewrite still exceeded the output limit');
  }

  return rewriteResult.content.trim();
}

module.exports = { requestChatReply };