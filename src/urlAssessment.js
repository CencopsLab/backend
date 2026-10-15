const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const { checkUrl } = require('./checks');

function unavailable(result, reason) {
  const recommendation = result.verdict === 'suspicious'
    ? 'avoid'
    : result.verdict === 'caution'
      ? 'caution'
      : 'unavailable';
  return {
    ...result,
    urlAssessment: {
      status: 'unavailable',
      riskScore: Number.isInteger(result.riskScore) ? result.riskScore : null,
      recommendation,
      reason,
    },
  };
}

async function reviewUrlWithGroq(url, options = {}) {
  const result = checkUrl(url);
  const apiKey = options.apiKey ?? process.env.GROQ_API_KEY;
  const model = options.model ?? process.env.GROQ_MODEL;
  const fetchImpl = options.fetchImpl ?? fetch;

  if (!apiKey || !model) {
    return unavailable(result, 'AI URL review is not configured. The deterministic URL checks are shown instead.');
  }

  try {
    const response = await fetchImpl(GROQ_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        temperature: 0.1,
        max_tokens: 200,
        messages: [
          {
            role: 'system',
            content: 'Assess only visible URL text for common scam indicators. Do not claim that the site was visited or that live reputation was checked. Return JSON only: {"risk_score": integer 0-100, "reason": short explanation}. This heuristic score is not a probability and a low score does not prove safety.',
          },
          { role: 'user', content: `URL to assess: ${url}` },
        ],
      }),
    });
    if (!response.ok) {
      throw new Error(`Groq URL assessment returned HTTP ${response.status}`);
    }

    const payload = await response.json();
    const content = payload?.choices?.[0]?.message?.content;
    const assessment = JSON.parse(content);
    const modelScore = Number(assessment?.risk_score);
    if (!Number.isFinite(modelScore) || modelScore < 0 || modelScore > 100 || typeof assessment?.reason !== 'string') {
      throw new Error('Groq URL assessment returned an invalid response');
    }

    const warningCount = result.checks?.filter((check) => check.status === 'warning').length ?? 0;
    const warningFloor = warningCount >= 3 ? 70 : warningCount === 2 ? 55 : warningCount === 1 ? 35 : 0;
    const riskScore = Math.max(
      Math.round(modelScore),
      warningFloor,
      Number.isInteger(result.riskScore) ? result.riskScore : 0,
      result.verdict === 'caution' ? 25 : 0,
      result.verdict === 'suspicious' ? 70 : 0,
    );
    const recommendation = riskScore >= 70
      ? 'avoid'
      : riskScore >= 25
        ? 'caution'
        : 'no_obvious_risk';
    const reason = assessment.reason.trim();
    const verdict = result.verdict === 'suspicious' || recommendation === 'avoid'
      ? 'suspicious'
      : result.verdict === 'caution' || recommendation === 'caution'
        ? 'caution'
        : result.verdict;
    const guidance = result.guidance
      ? {
        ...result.guidance,
        verdict,
        ...(verdict !== result.verdict
          ? {
            findings: [...result.guidance.findings, 'The URL-only heuristic assessment indicates elevated risk.'],
            meaning: 'The visible URL produced an elevated heuristic risk estimate. This estimate is not a live reputation check and does not confirm that the site is malicious.',
          }
          : {}),
      }
      : result.guidance;

    return {
      ...result,
      verdict,
      ...(guidance ? { guidance } : {}),
      summary: `${result.verdict === 'caution' ? `${result.summary} ` : ''}Heuristic risk estimate: ${riskScore}/100. ${reason} This is not confirmation that the site is safe.`,
      urlAssessment: { status: 'available', riskScore, recommendation, reason },
    };
  } catch (error) {
    console.error('Groq URL assessment failed:', error.message);
    return unavailable(result, 'AI URL review is unavailable. The deterministic URL checks are shown instead.');
  }
}

module.exports = { reviewUrlWithGroq };
