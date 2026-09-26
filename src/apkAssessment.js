const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

async function assessApkPermissions(permissions, options = {}) {
  const apiKey = options.apiKey ?? process.env.GROQ_API_KEY;
  const model = options.model ?? process.env.GROQ_MODEL;
  const fetchImpl = options.fetchImpl ?? fetch;
  const riskyPermissions = permissions.filter((permission) => /SMS|CALL_LOG|RECORD_AUDIO|CAMERA|LOCATION|CONTACTS|READ_PHONE|INSTALL_PACKAGES|ACCESSIBILITY|SYSTEM_ALERT/i.test(permission));

  const fallback = {
    verdict: riskyPermissions.length >= 3 ? 'suspicious' : 'unknown',
    finding: riskyPermissions.length
      ? `The app requests access that can expose ${riskyPermissions.length} sensitive device feature${riskyPermissions.length === 1 ? '' : 's'}.`
      : 'No commonly sensitive access request was identified.',
    meaning: 'Access requests can be legitimate for an app\'s features, but unusual combinations increase the possibility of misuse.',
  };

  if (!apiKey || !model || permissions.length === 0) return fallback;

  try {
    const response = await fetchImpl(GROQ_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        temperature: 0.1,
        max_tokens: 180,
        messages: [
          { role: 'system', content: 'Assess Android app access requests for citizen safety. Return JSON only with verdict (safe, suspicious, unknown), finding, and meaning. Do not claim malware certainty. Explain possibility of misuse, not certainty.' },
          { role: 'user', content: `Access requests: ${permissions.join(', ')}` },
        ],
      }),
    });
    if (!response.ok) return fallback;
    const payload = await response.json();
    const content = payload?.choices?.[0]?.message?.content || '';
    const parsed = JSON.parse(content.replace(/^```json\s*|\s*```$/g, '').trim());
    if (!['safe', 'suspicious', 'unknown'].includes(parsed.verdict) || !parsed.finding || !parsed.meaning) return fallback;
    return { verdict: parsed.verdict, finding: String(parsed.finding), meaning: String(parsed.meaning) };
  } catch {
    return fallback;
  }
}

module.exports = { assessApkPermissions };
