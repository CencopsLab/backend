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

  const missingDomain = urlLookup.domainExists === false;
  const riskScore = Math.max(missingDomain ? 90 : 80, assessment.urlAssessment.riskScore ?? 0);
  const reason = missingDomain
    ? 'The domain could not be found in public DNS. Scammers may use short-lived domains that disappear after a short time, so this is a strong warning signal. Temporary DNS or configuration issues can also cause this, so it does not prove the URL is a scam.'
    : 'The live lookup could not find the requested page. Treat this as a high-risk signal, not proof of maliciousness.';
  const guidance = assessment.guidance
    ? {
      ...assessment.guidance,
      verdict: 'suspicious',
      findings: [...assessment.guidance.findings, reason],
      meaning: missingDomain
        ? 'The domain was not found in public DNS. Short-lived scam domains can disappear, but temporary DNS or configuration issues are also possible; this result alone does not prove fraud.'
        : 'The live lookup did not find the requested page. This can happen for unavailable or removed pages and does not by itself prove fraud.',
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
