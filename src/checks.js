const { inspectApkPermissions } = require('./apkManifest');
const { assessApkPermissions } = require('./apkAssessment');
const dns = require('node:dns').promises;
const { isIP } = require('node:net');
const { parsePhoneNumberFromString } = require('libphonenumber-js/max');
const smsData = require('../data/sms.json');
const smsHeaders = require('../data/sms_header.json');

const SMS_CATEGORIES = {
  S: 'Service',
  P: 'Promotional',
  T: 'Transactional',
  G: 'Government',
};

const URL_SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly', 'lnkd.in',
  'tiny.cc', 'shorturl.at', 'rb.gy', 't.ly', 'v.gd', 'soo.gd', 'trib.al', 'bl.ink', 'short.io', 't2m.io',
];
const FREE_HOSTING_DOMAINS = [
  'vercel.app', 'onrender.com', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
  'github.io', 'fly.dev', 'railway.app', 'surge.sh', 'glitch.me', 'replit.app', 'repl.co',
  'herokuapp.com', 'herokussl.com', 'azurewebsites.net', 'appspot.com', 'blogspot.com', 'wordpress.com',
  'webflow.io', 'wixsite.com', 'weebly.com', '000webhostapp.com', 'infinityfreeapp.com',
  'sites.google.com',
];
const HOSTING_PLATFORMS = {
  'vercel.app': 'Vercel',
  'onrender.com': 'Render',
  'netlify.app': 'Netlify',
  'pages.dev': 'Cloudflare Pages',
  'workers.dev': 'Cloudflare Workers',
  'web.app': 'Firebase Hosting',
  'firebaseapp.com': 'Firebase Hosting',
  'github.io': 'GitHub Pages',
  'fly.dev': 'Fly.io',
  'railway.app': 'Railway',
  'surge.sh': 'Surge',
  'glitch.me': 'Glitch',
  'replit.app': 'Replit',
  'repl.co': 'Replit',
  'herokuapp.com': 'Heroku',
  'herokussl.com': 'Heroku',
  'azurewebsites.net': 'Azure App Service',
  'appspot.com': 'Google App Engine',
  'blogspot.com': 'Blogger',
  'wordpress.com': 'WordPress.com',
  'webflow.io': 'Webflow',
  'wixsite.com': 'Wix',
  'weebly.com': 'Weebly',
  '000webhostapp.com': '000webhost',
  'infinityfreeapp.com': 'InfinityFree',
  'sites.google.com': 'Google Sites',
};

function isDomainOrSubdomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function hostingPlatformFor(hostname) {
  return Object.entries(HOSTING_PLATFORMS).find(([domain]) => isDomainOrSubdomain(hostname, domain))?.[1]
    ?? FREE_HOSTING_DOMAINS.find((domain) => isDomainOrSubdomain(hostname, domain))
    ?? null;
}

function isPrivateIp(hostname) {
  const address = hostname.replace(/^\[|\]$/g, '');
  const version = isIP(address);
  if (version === 4) {
    const octets = address.split('.').map(Number);
    const [first, second] = octets;
    return first === 0 || first === 10 || first === 127
      || (first === 169 && second === 254)
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || (first === 100 && second >= 64 && second <= 127)
      || first >= 224;
  }
  if (version === 6) {
    const normalized = address.toLowerCase();
    return normalized === '::' || normalized === '::1'
      || normalized.startsWith('fc') || normalized.startsWith('fd')
      || normalized.startsWith('fe8') || normalized.startsWith('fe9')
      || normalized.startsWith('fea') || normalized.startsWith('feb')
      || normalized.startsWith('::ffff:127.')
      || normalized.startsWith('::ffff:10.')
      || normalized.startsWith('::ffff:192.168.');
  }
  return /(?:^|\.)localhost$|(?:^|\.)(?:local|internal|test|invalid)$/.test(address);
}

function urlRiskScore(checks, usesFreeHosting) {
  const weights = {
    'HTTPS connection': 25,
    'IP-based host': 25,
    'Private or local host': 30,
    'URL credentials': 35,
    'URL shortener': 20,
    'Internationalized host': 30,
    'Suspicious URL wording': 25,
    'Non-standard port': 10,
    'Unusually deep subdomain': 10,
  };
  const score = checks.reduce((total, check) => (
    check.status === 'warning' ? total + (weights[check.name] ?? 0) : total
  ), usesFreeHosting ? 25 : 0);
  return Math.min(100, score);
}

function result(verdict, summary, scannedTarget, extra = {}) {
  return {
    verdict,
    summary,
    scannedTarget,
    ...extra,
  };
}

function userGuidance(verdict, findings, meaning, actions) {
  return { findings, meaning, actions, verdict };
}

function checkUrl(value) {
  const checks = [];
  const addCheck = (name, status, detail) => checks.push({ name, status, detail });
  if (typeof value !== 'string' || !value.trim() || value.length > 2048) {
    addCheck('URL format', 'warning', 'Enter a non-empty web address no longer than 2048 characters.');
    return result('unknown', 'The URL is empty or too long to assess.', String(value ?? ''), {
      checks,
      scanType: 'url',
      guidance: userGuidance('unknown', ['A valid web address was not provided.'], 'The address could not be assessed.', ['Check the address and try again.']),
    });
  }
  const scannedTarget = value.trim();
  let parsed;
  try {
    parsed = new URL(scannedTarget);
  } catch {
    addCheck('URL format', 'warning', 'The address could not be parsed as a URL.');
    return result('unknown', 'The URL format could not be checked.', scannedTarget, { checks, scanType: 'url', guidance: userGuidance('unknown', ['The address could not be checked.'], 'A malformed address cannot be reliably assessed.', ['Confirm the address with the sender before opening it.']) });
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    addCheck('URL protocol', 'warning', 'Only HTTP and HTTPS addresses are supported by this preliminary check.');
    return result('suspicious', 'Only HTTP and HTTPS URLs are supported by this preliminary check.', scannedTarget, { checks, scanType: 'url', guidance: userGuidance('suspicious', ['The address uses an unsupported connection type.'], 'The destination cannot be safely assessed through this check.', ['Do not open it; ask for an official HTTPS address.']) });
  }

  const usesHttp = parsed.protocol !== 'https:';
  const rawHostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const hostname = rawHostname.replace(/^www\./, '');
  const usesIpAddress = isIP(hostname.replace(/^\[|\]$/g, '')) !== 0;
  const usesPrivateHost = isPrivateIp(hostname);
  const usesCredentials = Boolean(parsed.username || parsed.password);
  const isShortenedUrl = URL_SHORTENER_DOMAINS.some((domain) => isDomainOrSubdomain(hostname, domain));
  const hostingPlatform = hostingPlatformFor(hostname);
  const usesFreeHosting = hostingPlatform !== null;
  const usesPunycode = hostname.split('.').some((label) => label.startsWith('xn--'));
  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const hasSuspiciousWording = /(?:login|signin|verify|account|secure|wallet|payment).{0,40}(?:urgent|suspend|confirm|unlock|claim|reward)|(?:urgent|suspend|confirm|unlock|claim|reward).{0,40}(?:login|signin|verify|account|secure|wallet|payment)/i.test(`${hostname}${pathAndQuery}`);
  const port = parsed.port ? Number(parsed.port) : null;
  const hasNonStandardPort = port !== null && ![80, 443].includes(port);
  const hasDeepSubdomain = hostname.split('.').length > 5 && !usesIpAddress;
  const reasons = [];
  if (usesHttp) reasons.push('it does not use HTTPS');
  if (usesIpAddress) reasons.push('it uses an IP address');
  if (usesPrivateHost) reasons.push('it points to a private or local address');
  if (usesCredentials) reasons.push('it embeds a username or password in the address');
  if (isShortenedUrl) reasons.push('it uses a URL shortener that hides the destination');
  if (usesPunycode) reasons.push('it uses an internationalized hostname that may visually imitate another domain');
  if (hasSuspiciousWording) reasons.push('it combines account/security wording with urgency or a reward');

  addCheck('HTTPS connection', usesHttp ? 'warning' : 'pass', usesHttp ? 'The address does not use HTTPS.' : 'The address uses HTTPS.');
  addCheck('IP-based host', usesIpAddress ? 'warning' : 'pass', usesIpAddress ? 'The host is an IP address rather than a domain name.' : 'The host is not an IP address.');
  addCheck('Private or local host', usesPrivateHost ? 'warning' : 'pass', usesPrivateHost ? 'The address points to a private, loopback, link-local, or local-only host.' : 'The host does not appear to be a private or local address.');
  addCheck('URL credentials', usesCredentials ? 'warning' : 'pass', usesCredentials ? 'The URL contains embedded login credentials, which can disguise the actual destination.' : 'No embedded username or password was found.');
  addCheck('URL shortener', isShortenedUrl ? 'warning' : 'pass', isShortenedUrl ? 'The final destination is hidden until the redirect is followed; verify it before opening.' : 'No recognized URL-shortening host was found.');
  addCheck('Free-hosting platform', usesFreeHosting ? 'info' : 'pass', usesFreeHosting ? `Hosted on a domain associated with ${hostingPlatform}. This shared/free hosting context is not proof that the site is malicious.` : 'No recognized free-hosting or shared-platform domain was found.');
  addCheck('Internationalized host', usesPunycode ? 'warning' : 'pass', usesPunycode ? 'The hostname contains a punycode label; inspect the spelling carefully for look-alike characters.' : 'No punycode hostname label was found.');
  addCheck('Suspicious URL wording', hasSuspiciousWording ? 'warning' : 'pass', hasSuspiciousWording ? 'The URL combines sign-in/security wording with urgency, account action, or a reward.' : 'No combined urgency and account-security wording was found.');
  addCheck('Non-standard port', hasNonStandardPort ? 'warning' : 'pass', hasNonStandardPort ? `The URL uses non-standard port ${port}. This is not proof of harm, but should be expected.` : 'No non-standard network port was specified.');
  addCheck('Unusually deep subdomain', hasDeepSubdomain ? 'info' : 'pass', hasDeepSubdomain ? 'The hostname has many subdomain levels; check which domain is actually registered.' : 'The hostname does not have an unusually large number of subdomain levels.');
  addCheck('Live threat reputation', 'unavailable', 'No threat-intelligence database was queried. The separate HTTP lookup checks reachability only, not whether a destination is safe.');

  const riskScore = urlRiskScore(checks, usesFreeHosting);
  const highRiskSignal = usesPrivateHost || usesCredentials || usesPunycode || hasSuspiciousWording;
  const warningCount = checks.filter((check) => check.status === 'warning').length;
  const verdict = highRiskSignal || warningCount >= 2 ? 'suspicious' : (usesFreeHosting || warningCount === 1) ? 'caution' : 'unknown';
  const findings = [];
  if (usesFreeHosting) findings.push(`The hostname is hosted on a domain associated with ${hostingPlatform}.`);
  findings.push(...reasons.map((reason) => `The URL ${reason}.`));
  if (findings.length === 0) findings.push('No listed warning pattern was found in the visible URL.');
  const summary = verdict === 'suspicious'
    ? `Suspicious URL indicators were found: ${reasons.join('; ')}. This is not a confirmed malicious-site finding.`
    : verdict === 'caution'
      ? usesFreeHosting && reasons.length === 0
        ? `This URL uses a ${hostingPlatform} hosting domain. Free/shared hosting is not proof of maliciousness, but verify who operates this specific site before trusting it.`
        : `Use caution: ${reasons.join('; ')}. This is not a confirmed malicious-site finding.`
      : 'No listed warning pattern was found in the visible URL. Live threat reputation was not checked; basic link reachability does not establish safety.';
  const meaning = usesFreeHosting
    ? `The address uses hosting associated with ${hostingPlatform}. These platforms host legitimate sites as well as user-created sites, so the platform alone cannot establish whether this site is safe.`
    : 'These indicators are based on the address only. The separate live lookup checks HTTP reachability without downloading page content, and no threat-intelligence source was queried.';
  const actions = verdict === 'suspicious'
    ? ['Do not open it unless you can verify the destination independently.', 'Avoid entering passwords, payment information, or personal details.']
    : ['Verify the site and its operator through an independent, trusted source.', 'Do not enter sensitive information unless you have confirmed the destination.'];
  return result(verdict, summary, scannedTarget, {
    riskScore,
    checks,
    scanType: 'url',
    guidance: userGuidance(verdict, findings, meaning, actions),
  });
}

async function checkEmail(value, options = {}) {
  const checks = [];
  const addCheck = (name, risky, detail) => checks.push({ name, status: risky ? 'warning' : 'pass', detail });
  const reasons = [];
  const emailMatch = value.trim().match(/^[^\s@]+@([^\s@]+)$/);
  const domain = emailMatch?.[1]?.toLowerCase();
  const mxLookup = options.mxLookup ?? (options.lookup ? null : dns.resolveMx);
  const addressLookup = options.lookup ?? options.addressLookup ?? dns.lookup;

  if (!domain || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(domain)) {
    addCheck('Email address format', true, 'Enter a complete email address with a domain, such as name@example.com.');
    return result('unknown', 'This does not look like a complete email address, so its domain could not be checked.', value, {
      checks,
      scanType: 'email',
      guidance: userGuidance('unknown', ['The email address format is invalid.'], 'No conclusion can be made about a sender from an incomplete or malformed address.', ['Enter a complete email address to check its domain.', 'Verify unexpected requests through a separate trusted channel.']),
    });
  }

  let domainExists = null;
  let mxRecordsFound = false;
  let mxLookupUnavailable = false;
  if (mxLookup) {
    try {
      const mxRecords = await mxLookup(domain);
      mxRecordsFound = Array.isArray(mxRecords) && mxRecords.length > 0;
      if (mxRecordsFound) domainExists = true;
    } catch (error) {
      // Fall back to address records because some domains use implicit MX.
      mxLookupUnavailable = !['ENOTFOUND', 'ENODATA', 'EAI_NONAME', 'ENOTIMP'].includes(error?.code);
    }
  }

  if (!mxRecordsFound) {
    try {
      await addressLookup(domain);
      domainExists = true;
    } catch (error) {
      const definitiveDnsErrors = new Set(['ENOTFOUND', 'ENODATA', 'EAI_NONAME', 'ENOTIMP']);
      if (definitiveDnsErrors.has(error?.code) && !mxLookupUnavailable) domainExists = false;
    }
  }

  if (domainExists === false) {
    reasons.push(`the sender domain ${domain} could not be found`);
    addCheck('Sender domain', true, `The domain ${domain} has no mail or address records.`);
  } else if (domainExists === null) {
    checks.push({ name: 'Sender domain', status: 'unavailable', detail: `The domain ${domain} could not be checked because DNS lookup is temporarily unavailable.` });
  } else {
    addCheck('Sender domain', false, mxRecordsFound
      ? `The domain ${domain} has mail-server records.`
      : `The domain ${domain} resolves to an address.`);
  }
  checks.push({ name: 'Message content, links, and sender authentication', status: 'unavailable', detail: 'Only an email address was provided. Message text, headers, SPF, DKIM, and DMARC were not checked.' });

  if (reasons.length) {
    return result('suspicious', `A sender-domain indicator was found: ${reasons.join(', ')}. This does not establish sender identity or intent.`, value, { checks, scanType: 'email', guidance: userGuidance('suspicious', reasons.map((reason) => `The supplied address has this domain indicator: ${reason}.`), 'Only the address and DNS availability were checked. The email content and sender identity were not verified.', ['Verify unexpected requests through a separate official channel.', 'Do not share OTPs, passwords, or payment details based on an email alone.']) });
  }
  if (domainExists === null) {
    return result('unknown', 'The email domain could not be checked right now. Try again when DNS or internet access is available.', value, { checks, scanType: 'email', guidance: userGuidance('unknown', ['The live domain lookup was unavailable.'], 'No conclusion can be made about the sender domain or the email.', ['Retry the scan or verify the sender using an official contact method.']) });
  }
  return result('unknown', 'The domain has DNS records, but the sender and email could not be authenticated. Only the address was checked.', value, { checks, scanType: 'email', guidance: userGuidance('unknown', [`The sender domain ${domain} has ${mxRecordsFound ? 'mail-server' : 'address'} records.`], 'DNS records show domain availability, not that this email came from its owner. Email content and authentication headers were not checked.', ['Verify unexpected requests using a separate official contact method.', 'Do not share credentials or payment information unless you trust the request.']) });
}

function parseSmsHeader(input) {
  const originalHeader = input.trim();
  const parts = originalHeader.split(/\s*-\s*/).map((part) => part.trim());
  const parsed = {
    originalHeader,
    header: '',
    tspCode: null,
    lsaCode: null,
    categoryCode: null,
    formatValid: true,
  };

  if (parts.length === 1) {
    parsed.header = parts[0];
  } else if (parts.length === 2) {
    if (parts[1].length === 1) {
      parsed.header = parts[0];
      parsed.categoryCode = parts[1].toUpperCase();
    } else if (parts[0].length === 2) {
      parsed.tspCode = parts[0][0].toUpperCase();
      parsed.lsaCode = parts[0][1].toUpperCase();
      parsed.header = parts[1];
    } else {
      parsed.header = parts[0];
      parsed.categoryCode = parts[1].toUpperCase();
      parsed.formatValid = false;
    }
  } else if (parts.length === 3) {
    parsed.header = parts[1];
    parsed.categoryCode = parts[2].toUpperCase();
    if (parts[0].length === 2) {
      parsed.tspCode = parts[0][0].toUpperCase();
      parsed.lsaCode = parts[0][1].toUpperCase();
    } else {
      parsed.formatValid = false;
    }
  } else {
    parsed.header = parts[0] || '';
    parsed.formatValid = false;
  }

  if (!parsed.header) parsed.formatValid = false;
  return parsed;
}

function checkSms(input) {
  const checks = [];
  const addCheck = (name, status, detail) => checks.push({ name, status, detail });
  const parsed = parseSmsHeader(input);
  const normalizedHeader = parsed.header.toLocaleUpperCase();
  const registeredHeader = smsHeaders.find((entry) => String(entry.header).trim().toLocaleUpperCase() === normalizedHeader);
  const provider = parsed.tspCode
    ? smsData.service_providers.find((entry) => entry.code.toUpperCase() === parsed.tspCode)
    : null;
  const serviceArea = parsed.lsaCode
    ? smsData.service_areas.find((entry) => entry.code.toUpperCase() === parsed.lsaCode)
    : null;
  const category = parsed.categoryCode ? SMS_CATEGORIES[parsed.categoryCode] : null;

  addCheck(
    'Header format',
    parsed.formatValid ? 'pass' : 'warning',
    parsed.formatValid
      ? 'The supplied value could be parsed as a header with optional TSP/LSA and category components.'
      : 'The supplied value does not match a supported header format; the first header segment was used for lookup.'
  );
  addCheck(
    'Principal Entity directory',
    registeredHeader ? 'pass' : 'warning',
    registeredHeader
      ? 'The header was found. This is not live TRAI/DLT verification.'
      : 'No matching header was found .'
  );

  if (parsed.tspCode) {
    addCheck(
      'Service Provider / TSP',
      provider ? 'pass' : 'warning',
      provider ? `Code ${parsed.tspCode} matches ${provider.name_of_service_provider}.` : `No service provider matches code ${parsed.tspCode} in the supplied data.`
    );
    addCheck(
      'Service Area / LSA',
      serviceArea ? 'pass' : 'warning',
      serviceArea ? `Code ${parsed.lsaCode} matches ${serviceArea.service_area}.` : `No service area matches code ${parsed.lsaCode} in the supplied data.`
    );
  }

  if (parsed.categoryCode) {
    addCheck(
      'Header category',
      category ? 'pass' : 'warning',
      category ? `Suffix ${parsed.categoryCode} means ${category}.` : `Suffix ${parsed.categoryCode} is not one of S, P, T, or G.`
    );
  } else {
    addCheck('Header category', 'unavailable', 'No category suffix was supplied.');
  }

  addCheck('Live TRAI / DLT registration and route', 'unavailable', 'The supplied files are offline reference data and cannot confirm current registration or the actual sender/route.');
  addCheck('Registered message template', 'unavailable', 'Only the SMS header is scanned; message content and template compliance are not checked.');

  const headerDetails = {
    originalHeader: parsed.originalHeader,
    serviceProviderCode: parsed.tspCode,
    serviceProvider: provider?.name_of_service_provider || null,
    serviceAreaCode: parsed.lsaCode,
    serviceArea: serviceArea?.service_area || null,
    header: parsed.header,
    principalEntityName: registeredHeader?.name || null,
    categoryCode: parsed.categoryCode,
    category,
  };

  const hasMetadataWarning = checks.some((check) => check.status === 'warning');
  const hasCompleteMetadata = Boolean(parsed.tspCode && parsed.lsaCode && parsed.categoryCode);
  const verdict = !registeredHeader || hasMetadataWarning
    ? 'suspicious'
    : hasCompleteMetadata
      ? 'safe'
      : 'likely_safe';

  return result(
    verdict,
    verdict === 'suspicious'
      ? 'The header has a format or reference-data warning. This does not prove fraud; live sender identity is not checked.'
      : verdict === 'safe'
        ? 'The header and supplied provider, area, and category data match. This does not confirm the live sender or message authenticity.'
        : 'The header matches supplied reference data, but some optional metadata was not provided. The live sender is not verified.',
    parsed.originalHeader,
    { checks, headerDetails, scanType: 'sms' }
  );
}

function checkMobile(value) {
  const checks = [];
  const addCheck = (name, status, detail) => checks.push({ name, status, detail });
  const input = value.trim();

  if (!/^\+?[0-9\s().-]+$/.test(input) || (input.match(/\+/g) || []).length > 1 || (input.includes('+') && !input.startsWith('+'))) {
    addCheck('Number format', 'warning', 'Use digits and standard phone-number separators only.');
    addCheck('Live verification', 'unavailable', 'Reachability, ownership, carrier, and virtual-line status were not checked.');
    return result('suspicious', 'This input is not a supported phone-number format.', value, { checks, scanType: 'mobile', guidance: userGuidance('suspicious', ['The number format could not be validated.'], 'An invalid or incomplete number cannot be reliably linked to a person or organisation.', ['Do not send money or share personal information until the number is independently verified.']) });
  }

  const phone = parsePhoneNumberFromString(input, 'IN');
  if (!phone) {
    addCheck('Country', 'warning', 'The number could not be parsed as an Indian phone number.');
    addCheck('Numbering plan', 'warning', 'The number could not be validated.');
    addCheck('Live verification', 'unavailable', 'Reachability, ownership, carrier, and virtual-line status were not checked.');
    return result('suspicious', 'The number could not be validated as an Indian mobile number.', value, { checks, scanType: 'mobile', guidance: userGuidance('suspicious', ['The number could not be validated as an Indian mobile number.'], 'Numbering data cannot confirm the owner or intent behind a number.', ['Verify the caller through an official number before responding.']) });
  }

  if (phone.country !== 'IN') {
    addCheck('Country', 'warning', `This number resolves to ${phone.country || 'a non-Indian or unsupported region'}, not India.`);
    addCheck('Numbering plan', 'info', 'The number was not assessed against India\'s numbering plan.');
    addCheck('Live verification', 'unavailable', 'Reachability, ownership, carrier, and virtual-line status were not checked.');
    return result('suspicious', 'This number does not belong to the Indian numbering region.', value, { checks, scanType: 'mobile', guidance: userGuidance('suspicious', ['The number is outside the Indian numbering region.'], 'This may be unexpected, but a country code alone does not prove fraud.', ['Do not share OTPs or financial information with an unexpected caller.']) });
  }

  addCheck('Country', 'pass', 'Country code and numbering region resolve to India (+91).');
  if (!phone.isValid()) {
    addCheck('Numbering plan', 'warning', 'The length or number range is not valid in the current numbering metadata.');
    addCheck('Live verification', 'unavailable', 'Reachability, ownership, carrier, and virtual-line status were not checked.');
    return result('suspicious', 'This number is not valid under the current Indian numbering plan.', value, { checks, scanType: 'mobile', guidance: userGuidance('suspicious', ['The number is not valid under the current numbering plan.'], 'A numbering check cannot confirm whether a caller is legitimate.', ['Verify the caller through an official channel.']) });
  }

  addCheck('Numbering plan', 'pass', 'The number matches a range and length in the current Indian numbering metadata.');
  const lineType = phone.getType();
  if (lineType === 'MOBILE') {
    addCheck('Line type', 'pass', 'Numbering metadata classifies this range as mobile.');
  } else if (lineType) {
    addCheck('Line type', 'warning', `Numbering metadata classifies this as ${lineType.toLowerCase().replace(/_/g, ' ')}, not mobile.`);
    addCheck('Live verification', 'unavailable', 'Reachability, ownership, carrier, and virtual-line status were not checked.');
    return result('suspicious', 'This is a valid Indian number, but its numbering range is not classified as mobile.', value, { checks, scanType: 'mobile', guidance: userGuidance('suspicious', ['The number is not classified as a mobile range.'], 'Numbering information cannot identify the caller or prove fraud.', ['Use an official contact number before sharing information.']) });
  } else {
    addCheck('Line type', 'info', 'The number is valid, but metadata could not classify its line type.');
  }

  const nationalNumber = phone.nationalNumber;
  const hasObviousPattern = /^(\d)\1{7,}$/.test(nationalNumber)
    || /^(0123456789|1234567890|9876543210|0987654321)$/.test(nationalNumber);
  addCheck(
    'Number pattern',
    hasObviousPattern ? 'warning' : 'pass',
    hasObviousPattern
      ? 'A repeated or sequential pattern can indicate a placeholder; it does not prove fraud.'
      : 'No obvious repeated or sequential placeholder pattern was detected.'
  );
  addCheck('SIM / virtual line', 'unavailable', 'Numbering metadata cannot prove a physical SIM, detect forwarding, or reliably identify VoIP.');
  addCheck('Reachability / ownership', 'unavailable', 'No call, SMS, OTP, subscriber, or current-carrier lookup was performed.');

  return result(
    'unknown',
    `This number matches an Indian mobile numbering range${hasObviousPattern ? ', but has a placeholder-like pattern' : ''}. This does not prove that it is active, owned by the claimed person, or safe.`,
    value,
    { checks, normalizedNumber: phone.number, scanType: 'mobile', guidance: userGuidance('unknown', [hasObviousPattern ? 'The number has a repeated or sequential pattern.' : 'The number matches an Indian mobile numbering range.'], 'Numbering checks cannot confirm reachability, ownership, or whether the caller is trustworthy.', ['Do not share OTPs, passwords, or payment details with an unexpected caller.', 'Verify the identity through an official channel.']) }
  );
}

async function checkFile(file, options = {}) {
  const name = file.originalname || 'uploaded file';
  const extension = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  const allowed = new Set(['apk', 'pdf', 'zip', 'jpg', 'jpeg', 'png', 'webp']);

  if (!allowed.has(extension)) {
    return result('unknown', 'File received, but this preliminary check does not inspect its contents.', name, { scanType: 'file', guidance: userGuidance('unknown', ['The file type was received but could not be checked.'], 'Its safety and intent could not be established.', ['Do not open or install it unless you trust the source.']) });
  }

  if (extension === 'apk') {
    try {
      const inspectPermissions = options.inspectApkPermissions ?? inspectApkPermissions;
      const assessPermissions = options.assessApkPermissions ?? assessApkPermissions;
      const permissions = await inspectPermissions(file.buffer);
      const permissionAssessment = await assessPermissions(permissions);
      const hasSmsPermission = permissions.some((permission) => /(?:READ|RECEIVE|SEND|WRITE)_SMS/i.test(permission));
      const assessedRiskScore = Math.max(0, Math.min(100, Math.round(Number(permissionAssessment.riskScore) || 0)));
      const riskScore = Math.max(hasSmsPermission ? 55 : 0, assessedRiskScore);
      const verdict = hasSmsPermission || permissionAssessment.verdict === 'suspicious' || riskScore >= 25 ? 'suspicious' : 'unknown';
      const findings = permissionAssessment.findings?.length
        ? permissionAssessment.findings
        : [permissionAssessment.finding];
      return result(
        verdict,
        `Heuristic risk estimate: ${riskScore}/100. Requested access does not prove the app is malicious or that access has been granted.`,
        name,
        {
          permissions,
          sensitivePermissions: permissionAssessment.sensitivePermissions ?? [],
          riskScore,
          checks: [
            { name: 'Cyber safety review', status: verdict === 'suspicious' ? 'warning' : 'info', detail: permissionAssessment.meaning },
          ],
          scanType: 'file',
          guidance: userGuidance(verdict, findings, permissionAssessment.meaning, permissionAssessment.actions),
        }
      );
    } catch (error) {
      console.error('APK manifest inspection failed:', error.message);
      const cannotVerify = error.code === 'APK_MANIFEST_MISSING'
        || error.code === 'APK_MANIFEST_ENCRYPTED'
        || /Could not read AndroidManifest\.xml/.test(`${error.stderr || ''} ${error.message}`);
      return result(
        cannotVerify ? 'malicious' : 'unknown',
        cannotVerify
          ? 'This app file could not be verified and is treated as dangerous. Do not install it; get the app from an official source.'
          : 'The APK was received, but app access could not be inspected in this environment.',
        name,
        {
          riskScore: cannotVerify ? 100 : null,
          checks: [{
            name: 'File safety',
            status: cannotVerify ? 'warning' : 'unavailable',
            detail: cannotVerify
              ? 'Treat this file as dangerous and do not install it.'
              : 'App access inspection was unavailable; no malware conclusion can be made.',
          }],
          scanType: 'file',
          guidance: userGuidance(cannotVerify ? 'malicious' : 'unknown', [cannotVerify ? 'This app file could not be verified.' : 'App access could not be inspected.'], cannotVerify ? 'An unverified app file could put your device and accounts at risk.' : 'The app could not be assessed in this environment.', ['Do not install this file.', 'Use an official app store or verified publisher instead.'])
        }
      );
    }
  }

  return result('unknown', `Received ${extension.toUpperCase()} file. Content could not be checked.`, name, { scanType: 'file', guidance: userGuidance('unknown', ['The file content could not be checked.'], 'Its safety and intent could not be established.', ['Do not open it unless you trust the source.']) });
}

function runTextCheck(type, value, options = {}) {
  if (type === 'email') return checkEmail(value, options);
  if (type === 'sms') return checkSms(value);
  if (type === 'mobile') return checkMobile(value);
  return null;
}

module.exports = { checkUrl, checkFile, parseSmsHeader, runTextCheck };
