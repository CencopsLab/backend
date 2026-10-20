const { checkUrl } = require('./checks');

function assessUrl(url) {
  const result = checkUrl(url);
  const riskScore = Math.max(
    Number.isInteger(result.riskScore) ? result.riskScore : 0,
    result.verdict === 'caution' ? 25 : 0,
    result.verdict === 'suspicious' ? 70 : 0,
  );
  const recommendation = riskScore >= 70
    ? 'avoid'
    : riskScore >= 25
      ? 'caution'
      : 'no_obvious_risk';
  const reason = result.guidance?.findings.join(' ')
    || 'No assessable URL findings were produced by the local checks.';

  return {
    ...result,
    summary: `Heuristic risk estimate: ${riskScore}/100. ${reason} This is not confirmation that the site is safe.`,
    urlAssessment: { status: 'available', riskScore, recommendation, reason },
  };
}

function applyLookupPriority(assessment, urlLookup) {
  if (urlLookup.status !== 'not_found') return assessment;

  const riskScore = Math.max(80, assessment.urlAssessment.riskScore ?? 0);
  const reason = 'The live lookup could not find the domain or requested page. Treat this as a high-risk signal, not proof of maliciousness.';
  const guidance = assessment.guidance
    ? {
      ...assessment.guidance,
      verdict: 'suspicious',
      findings: [...assessment.guidance.findings, reason],
      meaning: 'The live lookup did not find the domain or requested page. This can happen for unavailable or removed pages and does not by itself prove fraud.',
    }
    : assessment.guidance;

  return {
    ...assessment,
    verdict: 'suspicious',
    riskScore,
    summary: `Heuristic risk estimate: ${riskScore}/100. ${reason}`,
    ...(guidance ? { guidance } : {}),
    urlAssessment: {
      ...assessment.urlAssessment,
      riskScore,
      recommendation: 'avoid',
      reason,
    },
  };
}

module.exports = { applyLookupPriority, assessUrl };
