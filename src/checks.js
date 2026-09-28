const { inspectApkPermissions } = require('./apkManifest');
const { assessApkPermissions } = require('./apkAssessment');
const dns = require('node:dns').promises;
const { parsePhoneNumberFromString } = require('libphonenumber-js/max');
const smsData = require('../data/sms.json');
const smsHeaders = require('../data/sms_header.json');

const SMS_CATEGORIES = {
  S: 'Service',
  P: 'Promotional',
  T: 'Transactional',
  G: 'Government',
};

const URL_SUSPICIOUS_PATTERNS = [
  /javascript:/i,
  /(^|[./-])xn--/i,
  /(?:verify|login|signin|account|payment|urgent|reward|prize|claim)/i,
];
const URL_SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly', 'lnkd.in',
];
const FREE_HOSTING_DOMAINS = [
  'vercel.app', 'onrender.com', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
  'github.io', 'fly.dev', 'railway.app', 'surge.sh', 'glitch.me', 'replit.app', 'repl.co',
];

function isDomainOrSubdomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
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
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    addCheck('URL format', 'warning', 'The address could not be parsed as a URL.');
    return result('unknown', 'The URL format could not be checked.', value, { checks, scanType: 'url', guidance: userGuidance('unknown', ['The address could not be checked.'], 'A malformed address cannot be reliably assessed.', ['Confirm the address with the sender before opening it.']) });
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    addCheck('URL protocol', 'warning', 'Only HTTP and HTTPS addresses are supported by this preliminary check.');
    return result('suspicious', 'Only HTTP and HTTPS URLs are supported by this preliminary check.', value, { checks, scanType: 'url', guidance: userGuidance('suspicious', ['The address uses an unsupported connection type.'], 'The destination cannot be safely assessed through this check.', ['Do not open it; ask for an official HTTPS address.']) });
  }

  const usesHttp = parsed.protocol !== 'https:';
  const usesIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(parsed.hostname);
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');
  const isShortenedUrl = URL_SHORTENER_DOMAINS.some((domain) => isDomainOrSubdomain(hostname, domain));
  const usesFreeHosting = FREE_HOSTING_DOMAINS.some((domain) => isDomainOrSubdomain(hostname, domain));
  const hasSuspiciousPattern = URL_SUSPICIOUS_PATTERNS.some((pattern) => pattern.test(value));
  const reasons = [];
  if (usesHttp) reasons.push('it does not use HTTPS');
  if (usesIpAddress) reasons.push('it uses an IP address');
  if (isShortenedUrl) reasons.push('it uses a URL shortener that hides the destination');
  if (hasSuspiciousPattern) reasons.push('it contains a common phishing indicator');

  addCheck('HTTPS connection', usesHttp ? 'warning' : 'pass', usesHttp ? 'The address does not use HTTPS.' : 'The address uses HTTPS.');
  addCheck('IP-based host', usesIpAddress ? 'warning' : 'pass', usesIpAddress ? 'The host is an IP address rather than a domain name.' : 'The host is not an IP address.');
  addCheck('URL shortener', isShortenedUrl ? 'warning' : 'pass', isShortenedUrl ? 'The final destination is hidden until the redirect is followed; verify it before opening.' : 'No recognized URL-shortening host was found.');
  addCheck('Free-hosting platform', usesFreeHosting ? 'info' : 'pass', usesFreeHosting ? 'This is a free-hosting domain. Hosting on this platform is not proof of maliciousness; inspect the specific site carefully.' : 'No recognized free-hosting domain was found.');
  addCheck('Common phishing patterns', hasSuspiciousPattern ? 'warning' : 'pass', hasSuspiciousPattern ? 'A common phishing indicator was found in the address.' : 'No listed phishing pattern was found.');

  if (reasons.length > 0) {
    return result('suspicious', `Preliminary warning: ${reasons.join('; ')}. Do not enter credentials or payment details.`, value, { checks, scanType: 'url', guidance: userGuidance('suspicious', reasons.map((reason) => `The link ${reason}.`), 'The destination or intent is not sufficiently trustworthy to proceed without verification.', ['Do not click the link unless you are certain who sent it.', 'Verify the sender through another trusted channel.']) });
  }

  return result('safe', 'No obvious pattern was found in this preliminary check. It is not a guarantee that the site is safe.', value, { checks, scanType: 'url', guidance: userGuidance('safe', ['No obvious warning pattern was found in the address.'], 'A clean address does not prove that the destination or sender is safe.', ['Open it only if you trust the sender and expected the link.']) });
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
    return result('suspicious', 'This does not look like a complete email address.', value, {
      checks,
      scanType: 'email',
      guidance: userGuidance('suspicious', ['The email address format is invalid.'], 'The sender domain could not be checked.', ['Do not reply or share personal information.', 'Confirm the address through a trusted channel.']),
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
  const hasPressureOrRewardLanguage = /(urgent|immediately|suspended|verify|winner|prize|refund|payment)/i.test(value);
  const requestsSensitiveInformation = /(password|otp|one[- ]?time password|cvv|card|bank)/i.test(value);
  const containsLink = /(bit\.ly|tinyurl\.com|t\.co|https?:\/\/)/i.test(value);

  if (hasPressureOrRewardLanguage) {
    reasons.push('urgent or reward language');
  }
  if (requestsSensitiveInformation) {
    reasons.push('a request for sensitive information');
  }
  if (containsLink) {
    reasons.push('a link that needs independent verification');
  }

  addCheck('Urgency or reward wording', hasPressureOrRewardLanguage, hasPressureOrRewardLanguage ? 'Urgent or reward-related wording was found.' : 'No listed urgency or reward wording was found.');
  addCheck('Sensitive information terms', requestsSensitiveInformation, requestsSensitiveInformation ? 'Terms related to credentials or financial information were found.' : 'No listed credential or financial-information terms were found.');
  addCheck('Links requiring verification', containsLink, containsLink ? 'A link was found; verify its destination independently.' : 'No recognized link was found.');

  if (reasons.length) {
    return result('suspicious', `Preliminary warning: ${reasons.join(', ')}. Verify the sender through an official channel.`, value, { checks, scanType: 'email', guidance: userGuidance('suspicious', reasons.map((reason) => `The message contains ${reason}.`), 'These are common signs of impersonation or phishing, but they do not prove who sent the message.', ['Do not reply, click links, or share OTPs or payment details.', 'Verify the sender through the organisation\'s official channel.']) });
  }
  if (domainExists === null) {
    return result('unknown', 'The email domain could not be checked right now. Try again when DNS or internet access is available.', value, { checks, scanType: 'email', guidance: userGuidance('unknown', ['The live domain lookup was unavailable.'], 'No conclusion can be made about the sender domain or the email.', ['Retry the scan or verify the sender using an official contact method.']) });
  }
  return result('safe', 'The email domain has mail or address records and no obvious phishing signal was found. This does not verify the sender.', value, { checks, scanType: 'email', guidance: userGuidance('safe', [`The sender domain ${domain} has ${mxRecordsFound ? 'mail-server' : 'address'} records.`], 'A real domain can still be used for fraud or impersonation; DNS does not authenticate the sender.', ['Do not share OTPs, passwords, or payment details until you trust the sender and context.']) });
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
      ? 'The header was found in the supplied sms_header.json data. This is not live TRAI/DLT verification.'
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
    { checks, headerDetails }
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
      return result(
        permissionAssessment.verdict,
        `${permissions.length} app access request${permissions.length === 1 ? '' : 's'} found. Access requests alone do not prove fraud.`,
        name,
        {
          permissions,
          checks: [
            { name: 'App access', status: 'info', detail: `${permissions.length} access request${permissions.length === 1 ? '' : 's'} found for review.` },
          ],
          scanType: 'file',
          guidance: userGuidance(permissionAssessment.verdict, [permissionAssessment.finding], permissionAssessment.meaning, ['Install only from a trusted source.', 'Review whether each requested access is necessary before installing.']),
        }
      );
    } catch (error) {
      console.error('APK manifest inspection failed:', error.message);
      const manifestMissing = /Could not read AndroidManifest\.xml|Invalid AndroidManifest\.xml/.test(`${error.stderr || ''} ${error.message}`);
      return result(
        manifestMissing ? 'suspicious' : 'unknown',
        manifestMissing
          ? 'No readable app access information was found. This APK cannot be verified and may be malformed or repackaged; this is not proof of malware.'
          : 'The APK was received, but app access could not be inspected in this environment.',
        name,
        {
          checks: [{
            name: 'App access check',
            status: manifestMissing ? 'warning' : 'unavailable',
            detail: manifestMissing
              ? 'The app could not be verified. Do not install unless you can verify the source independently.'
              : 'App access inspection was unavailable; no malware conclusion can be made.',
          }],
          scanType: 'file',
          guidance: userGuidance(manifestMissing ? 'suspicious' : 'unknown', [manifestMissing ? 'The app could not be verified.' : 'App access could not be inspected.'], 'An unverified app may be malformed or repackaged, but this alone does not prove malware.', ['Do not install it unless the source and publisher are independently verified.'])
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
