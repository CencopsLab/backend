const assert = require('node:assert/strict');
const test = require('node:test');
const { checkFile, checkUrl, parseSmsHeader, runTextCheck } = require('../src/checks');
const { assessApkPermissions } = require('../src/apkAssessment');
const { extractManifestPermissions } = require('../src/apkManifest');
const { applyLookupPriority, assessUrl } = require('../src/urlAssessment');

test('uses local findings, score, and explanation for URLs without warning signals', () => {
  const result = assessUrl('https://innefu.com');

  assert.equal(result.urlAssessment.status, 'available');
  assert.equal(result.urlAssessment.riskScore, 0);
  assert.equal(result.urlAssessment.recommendation, 'no_obvious_risk');
  assert.match(result.urlAssessment.reason, /No listed warning pattern/);
  assert.doesNotMatch(result.urlAssessment.reason, /random string|phishing/i);
  assert.match(result.summary, /0\/100/);
});

test('repeated URL assessments have the same local score and explanation', () => {
  const firstResult = assessUrl('https://example.com');
  const secondResult = assessUrl('https://example.com');

  assert.equal(firstResult.urlAssessment.riskScore, secondResult.urlAssessment.riskScore);
  assert.equal(firstResult.urlAssessment.recommendation, secondResult.urlAssessment.recommendation);
  assert.equal(firstResult.urlAssessment.reason, secondResult.urlAssessment.reason);
});

test('deterministic URL warning signals determine the score and explanation', () => {
  const result = assessUrl('http://bit.ly/urgent');

  assert.equal(result.urlAssessment.riskScore, 70);
  assert.equal(result.urlAssessment.recommendation, 'avoid');
  assert.equal(result.verdict, 'suspicious');
  assert.match(result.urlAssessment.reason, /shortener|HTTPS/i);
});

test('preserves a hosting-platform caution using local URL checks', () => {
  const result = assessUrl('https://abc.onrender.com');

  assert.equal(result.verdict, 'caution');
  assert.equal(result.urlAssessment.recommendation, 'caution');
  assert.equal(result.urlAssessment.riskScore, 25);
  assert.match(result.urlAssessment.reason, /Render/);
});

test('raises URL risk to at least 80 when live lookup cannot find the domain or page', () => {
  const result = applyLookupPriority(assessUrl('https://example.com'), {
    status: 'not_found',
    domainExists: true,
    httpStatus: 404,
    detail: 'The requested page could not be found.',
  });

  assert.equal(result.riskScore, 80);
  assert.equal(result.urlAssessment.riskScore, 80);
  assert.equal(result.urlAssessment.recommendation, 'avoid');
  assert.equal(result.verdict, 'suspicious');
  assert.match(result.summary, /not proof of maliciousness/i);
  assert.equal(result.guidance.verdict, 'suspicious');
});

test('does not lower an existing deterministic score when lookup is not found', () => {
  const result = applyLookupPriority(assessUrl('http://user:pass@192.0.2.1:8080/urgent-login'), {
    status: 'not_found',
    domainExists: false,
    httpStatus: null,
    detail: 'The domain name could not be found in public DNS.',
  });

  assert.equal(result.riskScore, 100);
  assert.equal(result.urlAssessment.riskScore, 100);
});

test('does not apply lookup priority when live lookup is unavailable', () => {
  const assessment = assessUrl('https://example.com');
  const result = applyLookupPriority(assessment, {
    status: 'unavailable',
    domainExists: null,
    httpStatus: null,
    detail: 'The destination could not be reached.',
  });

  assert.equal(result.riskScore, assessment.riskScore);
  assert.equal(result.urlAssessment.recommendation, 'no_obvious_risk');
});

test('returns assessable URL signals for secure and suspicious addresses', () => {
  const secure = checkUrl('https://example.com');
  const suspicious = checkUrl('http://192.0.2.1/verify');

  assert.deepEqual(secure.checks.map((check) => check.status), [
    'pass', 'pass', 'pass', 'pass', 'pass', 'pass', 'pass', 'pass', 'pass', 'pass', 'unavailable',
  ]);
  assert.equal(suspicious.checks.filter((check) => check.status === 'warning').length, 2);
});

test('treats URL shorteners as concealment signals and free hosting as context only', () => {
  const shortener = checkUrl('https://bit.ly/a1b2');
  const hosted = checkUrl('https://login-example.vercel.app');

  assert.equal(shortener.checks.find((check) => check.name === 'URL shortener').status, 'warning');
  assert.equal(hosted.checks.find((check) => check.name === 'Free-hosting platform').status, 'info');
  assert.equal(hosted.verdict, 'caution');
  assert.match(hosted.summary, /Vercel/);
});

test('identifies Render subdomains and explains that shared hosting alone is not proof of harm', () => {
  const result = checkUrl('https://abc.onrender.com');
  const hostingCheck = result.checks.find((check) => check.name === 'Free-hosting platform');

  assert.equal(result.verdict, 'caution');
  assert.equal(result.riskScore, 25);
  assert.match(hostingCheck.detail, /Render/);
  assert.match(result.guidance.findings.join(' '), /Render/);
  assert.match(result.guidance.meaning, /not proof|cannot establish/i);
});

test('flags embedded credentials, punycode, private hosts, and combined phishing wording', () => {
  const credentialUrl = checkUrl('https://trusted.example@attacker.example/login');
  const punycodeUrl = checkUrl('https://xn--pple-43d.example/');
  const privateUrl = checkUrl('http://192.168.1.20/');
  const phishingUrl = checkUrl('https://account-urgent.example/verify');

  assert.equal(credentialUrl.checks.find((check) => check.name === 'URL credentials').status, 'warning');
  assert.equal(punycodeUrl.checks.find((check) => check.name === 'Internationalized host').status, 'warning');
  assert.equal(privateUrl.checks.find((check) => check.name === 'Private or local host').status, 'warning');
  assert.equal(phishingUrl.checks.find((check) => check.name === 'Suspicious URL wording').status, 'warning');
});

test('does not treat platform name look-alikes as a recognized hosting domain', () => {
  const result = checkUrl('https://onrender.com.attacker.example');
  assert.equal(result.checks.find((check) => check.name === 'Free-hosting platform').status, 'pass');
});

test('marks an APK with no readable Android manifest as malicious', async () => {
  const result = await checkFile(
    { originalname: 'missing-manifest.apk', buffer: Buffer.alloc(0) },
    { inspectApkPermissions: async () => { throw new Error('Could not read AndroidManifest.xml: missing'); } },
  );

  assert.equal(result.verdict, 'malicious');
  assert.equal(result.riskScore, 100);
  assert.equal(result.checks[0].status, 'warning');
  assert.match(result.summary, /could not be verified and is treated as dangerous/);
  assert.doesNotMatch(result.summary, /manifest/i);
});

test('marks an APK with encrypted contents as malicious', async () => {
  const result = await checkFile(
    { originalname: 'encrypted.apk', buffer: Buffer.alloc(0) },
    { inspectApkPermissions: async () => { throw Object.assign(new Error('encrypted archive'), { code: 'APK_MANIFEST_ENCRYPTED' }); } },
  );

  assert.equal(result.verdict, 'malicious');
  assert.equal(result.riskScore, 100);
  assert.deepEqual(result.guidance.actions, ['Do not install this file.', 'Use an official app store or verified publisher instead.']);
});

test('uses Groq to return concise scam-awareness guidance and a bounded risk score', async () => {
  let requestBody;
  const result = await assessApkPermissions(['android.permission.READ_SMS'], {
    apiKey: 'test-key',
    model: 'test-model',
    fetchImpl: async (_url, options) => {
      requestBody = JSON.parse(options.body);
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: JSON.stringify({
            risk_score: 82,
            finding: 'A malicious app could expose text messages and verification codes.',
            meaning: 'A fake banking app might misuse this access after installation.',
            actions: ['Install only from an official store.', 'Never share OTPs.'],
          }) } }],
        }),
      };
    },
  });

  assert.match(requestBody.messages[0].content, /For SMS, mention OTPs, bank alerts, or scam texts/);
  assert.match(requestBody.messages[0].content, /familiar words and short sentences/);
  assert.match(requestBody.messages[0].content, /installing the app and allowing its permissions are the user’s choice/);
  assert.match(requestBody.messages[0].content, /checking the app maker/);
  assert.match(requestBody.messages[1].content, /android\.permission\.READ_SMS/);
  assert.equal(result.verdict, 'suspicious');
  assert.equal(result.riskScore, 82);
  assert.deepEqual(result.sensitivePermissions, ['android.permission.READ_SMS']);
  assert.equal(result.actions.length, 2);
  assert.match(result.findings.join(' '), /Can read texts with OTPs and bank alerts/);
  assert.match(result.finding, /verification codes/);
});

test('flags the supplied sensitive permission families and sends the complete list for review', async () => {
  const permissions = [
    'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS',
    'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS', 'android.permission.SEND_SMS',
    'android.permission.READ_CALL_LOG', 'android.permission.WRITE_CALL_LOG',
    'android.permission.READ_PHONE_STATE', 'android.permission.READ_PHONE_NUMBERS', 'android.permission.CALL_PHONE',
    'android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION', 'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.CAMERA', 'android.permission.RECORD_AUDIO',
    'android.permission.READ_MEDIA_IMAGES', 'android.permission.READ_MEDIA_VIDEO', 'android.permission.READ_MEDIA_AUDIO',
    'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.BLUETOOTH_CONNECT', 'android.permission.BLUETOOTH_SCAN', 'android.permission.NEARBY_WIFI_DEVICES',
    'android.permission.POST_NOTIFICATIONS', 'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.PACKAGE_USAGE_STATS', 'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.FOREGROUND_SERVICE', 'android.permission.WAKE_LOCK',
    'android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.ACCESS_WIFI_STATE',
    'android.permission.CHANGE_WIFI_STATE', 'android.permission.VIBRATE', 'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.USE_FULL_SCREEN_INTENT', 'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
    'android.permission.DISABLE_KEYGUARD', 'android.permission.RESTART_PACKAGES', 'android.permission.KILL_BACKGROUND_PROCESSES',
    'android.permission.GET_TASKS', 'android.permission.WRITE_SETTINGS', 'android.permission.READ_SETTINGS',
    'android.permission.READ_CLIPBOARD', 'android.permission.ACCESS_NOTIFICATION_POLICY',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE', 'android.permission.BIND_DEVICE_ADMIN',
    'android.permission.USE_BIOMETRIC', 'android.permission.USE_FINGERPRINT',
  ];
  let requestBody;
  const result = await assessApkPermissions(permissions, {
    apiKey: 'test-key',
    model: 'test-model',
    fetchImpl: async (_url, options) => {
      requestBody = JSON.parse(options.body);
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: JSON.stringify({
          risk_score: 10,
          finding: 'Several requested capabilities could expose personal information.',
          meaning: 'Requested access is not proof of misuse.',
          actions: ['Uninstall apps from unverified sources.'],
        }) } }] }),
      };
    },
  });

  assert.equal(result.verdict, 'suspicious');
  assert.equal(result.riskScore, 95);
  const smsPermissions = permissions.filter((permission) => /(?:READ|RECEIVE|SEND|WRITE)_SMS/i.test(permission));
  assert.deepEqual(result.sensitivePermissions, [
    ...smsPermissions,
    ...permissions.filter((permission) => !smsPermissions.includes(permission)),
  ]);
  assert.ok(result.findings.length <= 6);
  assert.match(requestBody.messages[0].content, /prioritizing SMS first, then contacts, notification access, camera, and photos\/videos\/audio/);
  assert.ok(result.actions.length <= 3);
  assert.ok(requestBody.messages[1].content.includes(permissions.join(', ')));
  const smsFindingCount = result.findings.filter((finding) => finding.startsWith('SMS access:')).length;
  assert.ok(smsFindingCount >= 1);
  assert.match(result.findings[smsFindingCount], /Several requested capabilities/);
});

test('gives common network and vibration permissions a low nonzero score', async () => {
  const result = await assessApkPermissions([
    'android.permission.INTERNET',
    'android.permission.VIBRATE',
  ], { apiKey: '', model: '' });

  assert.equal(result.riskScore, 6);
  assert.equal(result.verdict, 'unknown');
  assert.deepEqual(result.sensitivePermissions, [
    'android.permission.INTERNET',
    'android.permission.VIBRATE',
  ]);
});

test('extracts bound service and admin receiver permissions from the manifest', () => {
  const permissions = extractManifestPermissions(`
    <manifest>
      <uses-permission android:name="android.permission.READ_SMS" />
      <application>
        <service android:name=".Helper" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
        </service>
        <service android:name=".NotificationReader" android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
        </service>
        <receiver android:name=".Admin" android:permission="android.permission.BIND_DEVICE_ADMIN">
        </receiver>
      </application>
    </manifest>
  `);

  assert.deepEqual(permissions, [
    'android.permission.READ_SMS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
  ]);
});

test('recovers permissions when the decoded manifest omits attribute names', async () => {
  const permissions = extractManifestPermissions(`
    <manifest>
      <uses-permission
        ="android.permission.SEND_SMS"
        tag="<string:2176>"
      >
      </uses-permission>
      <uses-permission
        ="android.permission.RECEIVE_SMS"
        tag="<string:5753>"
      >
      </uses-permission>
      <uses-permission
        ="example.permission.CUSTOM_ACCESS"
        tag="<string:991>"
      >
      </uses-permission>
      <permission name="example.UNRELATED_PERMISSION" />
    </manifest>
  `);

  assert.deepEqual(permissions, [
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'example.permission.CUSTOM_ACCESS',
  ]);

  const assessment = await assessApkPermissions(permissions, { apiKey: '', model: '' });
  assert.equal(assessment.verdict, 'suspicious');
  assert.equal(assessment.riskScore, 95);
});

test('flags SMS access as suspicious when Groq is unavailable', async () => {
  const result = await assessApkPermissions(['android.permission.READ_SMS'], {
    apiKey: '',
    model: 'test-model',
  });

  assert.equal(result.verdict, 'suspicious');
  assert.equal(result.riskScore, 55);
  assert.match(result.finding, /Can read texts with OTPs and bank alerts/);
  assert.equal(result.actions.length, 3);
  assert.match(result.meaning, /Installing the app is your choice/);
  assert.match(result.actions.join(' '), /Allow only access you trust/);
});

test('always marks SMS permission suspicious even if the assessment returns a low score', async () => {
  for (const permission of ['READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'WRITE_SMS']) {
    const result = await checkFile(
      { originalname: 'sms-access.apk', buffer: Buffer.alloc(0) },
      {
        inspectApkPermissions: async () => [`android.permission.${permission}`],
        assessApkPermissions: async () => ({
          verdict: 'unknown',
          riskScore: 4,
          finding: 'Low risk.',
          findings: ['Low risk.'],
          meaning: 'This scan is guidance, not proof of harm. Installing the app is your choice; allow only access you trust.',
          actions: ['Review access.'],
        }),
      },
    );

    assert.equal(result.verdict, 'suspicious', permission);
    assert.equal(result.riskScore, 55, permission);
    assert.match(result.guidance.meaning, /Installing the app is your choice/);
  }
});

test('explains SMS and contacts misuse directly in the scan guidance', async () => {
  const result = await checkFile(
    { originalname: 'suspicious.apk', buffer: Buffer.alloc(0) },
    {
      inspectApkPermissions: async () => [
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_CONTACTS',
        'android.permission.READ_SMS',
      ],
      assessApkPermissions: async (permissions) => assessApkPermissions(permissions, { apiKey: '', model: '' }),
    },
  );

  assert.equal(result.verdict, 'suspicious');
  assert.match(result.guidance.findings.join(' '), /OTPs and bank alerts/);
  assert.match(result.guidance.findings.join(' '), /copy or change your contacts/);
  assert.match(result.guidance.findings[0], /^SMS access:/);
  assert.deepEqual(result.sensitivePermissions.slice(0, 2), [
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
  ]);
  assert.match(result.guidance.meaning, /Installing the app is your choice/);
  assert.match(result.guidance.actions.join(' '), /Never share an OTP/);
});

test('keeps APK tool failures unrelated to the manifest as unknown', async () => {
  const result = await checkFile(
    { originalname: 'tool-error.apk', buffer: Buffer.alloc(0) },
    { inspectApkPermissions: async () => { throw new Error('Python runtime unavailable'); } },
  );

  assert.equal(result.verdict, 'unknown');
  assert.equal(result.checks[0].status, 'unavailable');
});

test('keeps an email unknown when its domain resolves but sender authentication is unavailable', async () => {
  const result = await runTextCheck('email', 'abc123@xyz.com', { lookup: async () => ({ address: '93.184.216.34', family: 4 }) });

  assert.equal(result.verdict, 'unknown');
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

test('keeps an email unknown when address records exist but sender authentication is unavailable', async () => {
  let addressLookups = 0;
  const result = await runTextCheck('email', 'abc123@example.com', {
    mxLookup: async () => [],
    addressLookup: async () => { addressLookups += 1; return { address: '192.0.2.1', family: 4 }; },
  });

  assert.equal(result.verdict, 'unknown');
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

test('looks up provider, service area, principal entity, and category without calling the header safe', () => {
  const result = runTextCheck('sms', 'AA - IOCXRP - S');

  assert.equal(result.verdict, 'safe');
  assert.equal(result.scanType, 'sms');
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

test('looks up a header and service suffix when the TSP/LSA prefix is omitted', () => {
  const result = runTextCheck('sms', 'IOCXRP-S');

  assert.equal(result.verdict, 'likely_safe');
  assert.equal(result.headerDetails.header, 'IOCXRP');
  assert.equal(result.headerDetails.principalEntityName, 'iNDIAN OIL CORPORATION LIMITED');
  assert.equal(result.headerDetails.serviceProvider, null);
  assert.equal(result.headerDetails.serviceArea, null);
  assert.equal(result.headerDetails.categoryCode, 'S');
  assert.equal(result.headerDetails.category, 'Service');
  assert.equal(result.checks.find((check) => check.name === 'Header format').status, 'pass');
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