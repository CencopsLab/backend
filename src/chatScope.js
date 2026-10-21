const DIRECT_CYBER_TOPIC_PATTERN = /\b(?:cyber(?:security|crime)?|cyber crime|online safety|internet safety|digital safety|digital arrest|arrest scam|password|passcode|passphrase|otp|one.time password|mfa|2fa|authenticat\w*|phish(?:ing)?|phising|phshing|scam|fraud|hack(?:ed|ing)?|malware|virus|ransomware|spyware|data breach|data leak|identity theft|social engineering|sim swap|spoof(?:ing)?|sextortion|doxxing|keylogger|spyware|firewall|antivirus|vpn|apk|android package|1930)\b|https?:\/\/|www\.|साइबर|सुरक्षा|ऑनलाइन|इंटरनेट|डिजिटल अरेस्ट|डिजिटल गिरफ्तारी|साइबर अपराध|साइबर क्राइम|पासवर्ड|ओटीपी|धोखाधड़ी|ठगी|फ़िशिंग|फिशिंग|सिम स्वैप|यूपीआई धोखाधड़ी|सायबर|ਸੁਰੱਖਿਆ|ਆਨਲਾਈਨ|ਇੰਟਰਨੈੱਟ|ਡਿਜੀਟਲ ਅਰੇਸਟ|ਡਿਜੀਟਲ ਗ੍ਰਿਫਤਾਰੀ|ਸਾਇਬਰ ਅਪਰਾਧ|ਪਾਸਵਰਡ|ਓਟੀਪੀ|ਧੋਖਾਧੜੀ|ਠੱਗੀ|ਸਿਮ ਸਵੈਪ|ਯੂਪੀਆਈ ਧੋਖਾਧੜੀ/i;
const INDIA_SCAM_LURE_PATTERN = /\b(?:e[\s-]?challan|challan|traffic fine|traffic police|parivahan|m[\s-]?parivahan|adani gas|gas bill|iocl|indane|bharat gas|hp gas|lpg bill|hdfc|axis(?: bank)?|icici|sbi|state bank of india|pnb|punjab national bank|canara(?: bank)?|union bank|bank of baroda|bank of india|indian bank|idbi|uco bank|kotak(?: mahindra)?|idfc first|yes bank|indusind|federal bank|au small finance|rbl bank|bandhan bank|bajaj finance|credit card|debit card|card block(?:ed)?|card.{0,12}(?:expire|update|verify)|bank.{0,12}(?:kyc|verify|update|block)|kyc.{0,12}(?:bank|card|update)|pm[\s-]?(?:kisan|kisaan)|pm[\s-]?yojan[ae]|pm scheme|government scheme|pension schemes?|pension.{0,12}(?:kyc|verify|update|stop|hold)|jeevan pramaan|loan app|instant loan|loan.{0,12}(?:app|approval|repay|offer)|invitation card|invite card|wedding card|shaadi card|nimantran card|gaming app|gaming apk|poker|teen patti|teenpatti|rummy app|online rummy|fastag|electricity bill|power bill|bill.{0,12}(?:due|disconnect|update|pay)|electricity.{0,12}(?:disconnect|bill))\b|ई[\s-]?चालान|चालान|परिवहन|पेंशन योजना|पीएम किसान|पीएम योजना|गैस बिल|बैंक केवाईसी|लोन ऐप|निमंत्रण कार्ड|शादी का कार्ड|टीन पट्टी|ਰਜਿਸਟਰੀ ਚਲਾਨ|ਚਲਾਨ|ਪੈਨਸ਼ਨ ਯੋਜਨਾ|ਪੀਐਮ ਕਿਸਾਨ|ਗੈਸ ਬਿੱਲ|ਲੋਨ ਐਪ|ਸੱਦਾ ਕਾਰਡ|ਟੀਨ ਪੱਤੀ/i;
const SOCIAL_ENGINEERING_PATTERN = /\b(?:impersonat\w*|pretend(?:ed|ing)? to be|fake (?:police|bank|courier|customer support|tech support)|remote access|screen.?sharing|investment scam|job scam|romance scam|parcel scam|courier scam|fake arrest|threaten(?:ed|ing)? to arrest|demand\w* money|unauthori[sz]ed (?:transaction|payment|login|access)|stolen (?:identity|password|credentials)|recovery code|verification code|one.time code|upi pin|card cvv|lost (?:mobile|phone|network|signal|cellular service)|no (?:mobile )?signal|stopped receiving (?:bank )?(?:codes|otps|sms)|sim swap)\b|पुलिस बनकर|बैंक अधिकारी बनकर|पैसे मांग|पैसे माँग|खाता हैक|नकली कॉल|फर्जी कॉल|संदिग्ध लिंक|नकली लिंक|सिग्नल नहीं|नेटवर्क बंद|ओटीपी नहीं आ|ਸਿਮ ਸਵੈਪ|ਸਿਗਨਲ ਨਹੀਂ|ਨੈੱਟਵਰਕ ਬੰਦ|ਓਟੀਪੀ ਨਹੀਂ ਆ/i;
const DIGITAL_OBJECT = '(?:account|email|e-mail|mailbox|inbox|profile|login|password|link|lnk|website|web site|url|wifi|wi-fi|network|phone|device|sim|bank|upi|card|payment|transaction|message|email address|apk|app|file|ईमेल|खाता|मोबाइल|फोन|लिंक|वेबसाइट|बैंक|यूपीआई|सिम|एपीके|ऐप|फ़ाइल|ਖਾਤਾ|ਮੋਬਾਈਲ|ਫ਼ੋਨ|ਲਿੰਕ|ਵੈੱਬਸਾਈਟ|ਬੈਂਕ|ਸਿਮ|ਐਪ|ਫ਼ਾਈਲ)';
const SECURITY_ACTION = '(?:hack(?:ed|ing)?|compromis(?:ed|e)|breach(?:ed)?|steal(?:ing)?|stolen|secure|protect|safe|safety|recover|lock(?:ed)?|suspicious|suspicous|unsafe|phish(?:ing)?|phising|phshing|fraud|scam|unauthori[sz]ed|access(?:ed)?|take[n]? over|report|verify|reset|change|share|send|install|माँग|मांग|हैक|चोरी|सुरक्षित|सुरक्षा|संदिग्ध|धोखाधड़ी|ठगी|शक|ਸ਼ੱਕੀ|ਹੈਕ|ਚੋਰੀ|ਸੁਰੱਖਿਅਤ|ਸੁਰੱਖਿਆ|ਧੋਖਾਧੜੀ|ਠੱਗੀ|ਸ਼ੱਕ)';
const SECURITY_CONTEXT_PATTERN = new RegExp(`(?:${DIGITAL_OBJECT}).{0,45}(?:${SECURITY_ACTION})|(?:${SECURITY_ACTION}).{0,45}(?:${DIGITAL_OBJECT})`, 'i');
const CYBER_TOPIC_PATTERNS = [DIRECT_CYBER_TOPIC_PATTERN, INDIA_SCAM_LURE_PATTERN, SOCIAL_ENGINEERING_PATTERN, SECURITY_CONTEXT_PATTERN];
const FOLLOW_UP_PATTERN = /^(?:and|also|then|so|why|how|what about|can you explain|please explain|tell me more|what should i do|is it|does it|will it|can i|should i|what if|any other|which one|which|that|it|they|them)\b/i;
const GREETING_PATTERN = /^(?:hi+|hello+|hey+|howdy|good morning|good afternoon|good evening|how are you|how's it going|thanks|thank you|bye|goodbye|नमस्ते|नमस्कार|हाय|ਸਤ ਸ੍ਰੀ ਅਕਾਲ|ਸਤਿ ਸ੍ਰੀ ਅਕਾਲ|ਹੈਲੋ|ਧੰਨਵਾਦ)(?:\s+(?:there|cyber\s*sahayak|cybersahayak|assistant))?[!.,?\s]*$/i;
const ACCOUNT_COMPROMISE_PATTERN = /\b(?:hack(?:ed)?|compromis(?:ed|e)|taken over|stolen|breached?)\b/i;
const ACCOUNT_REFERENCE_PATTERN = /\b(?:account|email|e-mail|mailbox|inbox|profile)\b/i;

const GREETING_REPLIES = {
  en: 'Hi! I’m Cyber Sahayak. I can help with cybersecurity and online safety. What would you like to know?',
  hi: 'नमस्ते! मैं साइबर सहायक हूँ। मैं साइबर सुरक्षा और ऑनलाइन सुरक्षा में मदद कर सकता हूँ। आप क्या जानना चाहते हैं?',
  pa: 'ਸਤ ਸ੍ਰੀ ਅਕਾਲ! ਮੈਂ ਸਾਈਬਰ ਸਹਾਇਕ ਹਾਂ। ਮੈਂ ਸਾਇਬਰ ਸੁਰੱਖਿਆ ਅਤੇ ਆਨਲਾਈਨ ਸੁਰੱਖਿਆ ਬਾਰੇ ਮਦਦ ਕਰ ਸਕਦਾ ਹਾਂ। ਤੁਸੀਂ ਕੀ ਜਾਣਨਾ ਚਾਹੁੰਦੇ ਹੋ?',
};

const OUT_OF_SCOPE_REPLIES = {
  en: 'I can only help with cybersecurity and online safety. Ask me about scams, account security, suspicious links, malware safety, or reporting cybercrime.',
  hi: 'मैं केवल साइबर सुरक्षा और ऑनलाइन सुरक्षा में मदद कर सकता हूँ। धोखाधड़ी, खाते की सुरक्षा, संदिग्ध लिंक, मैलवेयर से बचाव या साइबर अपराध की रिपोर्टिंग के बारे में पूछें।',
  pa: 'ਮੈਂ ਸਿਰਫ਼ ਸਾਇਬਰ ਸੁਰੱਖਿਆ ਅਤੇ ਆਨਲਾਈਨ ਸੁਰੱਖਿਆ ਬਾਰੇ ਮਦਦ ਕਰ ਸਕਦਾ ਹਾਂ। ਧੋਖਾਧੜੀ, ਖਾਤਾ ਸੁਰੱਖਿਆ, ਸ਼ੱਕੀ ਲਿੰਕ, ਮਾਲਵੇਅਰ ਤੋਂ ਬਚਾਅ ਜਾਂ ਸਾਇਬਰ ਅਪਰਾਧ ਦੀ ਰਿਪੋਰਟ ਬਾਰੇ ਪੁੱਛੋ।',
};

const COMPROMISED_ACCOUNT_REPLIES = {
  en: 'If your email account was hacked:\n1. From a trusted device, change its password on the provider’s official site and change any reused passwords.\n2. Sign out other sessions; check recovery details, forwarding rules, and filters for changes you did not make.\n3. Turn on MFA and secure accounts that use this email for password resets. Warn contacts about suspicious messages. Never share OTPs or recovery codes.',
  hi: 'अगर आपका ईमेल खाता हैक हुआ है:\n1. भरोसेमंद डिवाइस से सेवा प्रदाता की आधिकारिक वेबसाइट पर पासवर्ड बदलें और दोबारा इस्तेमाल किए गए पासवर्ड भी बदलें।\n2. बाकी सभी सेशन से साइन आउट करें; रिकवरी जानकारी, फ़ॉरवर्डिंग नियम और फ़िल्टर में अनजान बदलाव देखें।\n3. MFA चालू करें और इस ईमेल से जुड़े खातों को सुरक्षित करें। संदिग्ध संदेशों के बारे में संपर्कों को बताएं। OTP या रिकवरी कोड साझा न करें।',
  pa: 'ਜੇ ਤੁਹਾਡਾ ਈਮੇਲ ਖਾਤਾ ਹੈਕ ਹੋ ਗਿਆ ਹੈ:\n1. ਭਰੋਸੇਯੋਗ ਡਿਵਾਈਸ ਤੋਂ ਸੇਵਾ ਪ੍ਰਦਾਤਾ ਦੀ ਅਧਿਕਾਰਤ ਵੈੱਬਸਾਈਟ ਉੱਤੇ ਪਾਸਵਰਡ ਬਦਲੋ ਅਤੇ ਦੁਬਾਰਾ ਵਰਤੇ ਪਾਸਵਰਡ ਵੀ ਬਦਲੋ।\n2. ਹੋਰ ਸਾਰੇ ਸੈਸ਼ਨਾਂ ਤੋਂ ਸਾਈਨ ਆਉਟ ਕਰੋ; ਰਿਕਵਰੀ ਜਾਣਕਾਰੀ, ਫਾਰਵਰਡਿੰਗ ਨਿਯਮਾਂ ਅਤੇ ਫਿਲਟਰਾਂ ਵਿੱਚ ਅਣਜਾਣ ਤਬਦੀਲੀਆਂ ਵੇਖੋ।\n3. MFA ਚਾਲੂ ਕਰੋ ਅਤੇ ਇਸ ਈਮੇਲ ਨਾਲ ਜੁੜੇ ਖਾਤਿਆਂ ਨੂੰ ਸੁਰੱਖਿਅਤ ਕਰੋ। ਸ਼ੱਕੀ ਸੁਨੇਹਿਆਂ ਬਾਰੇ ਸੰਪਰਕਾਂ ਨੂੰ ਦੱਸੋ। OTP ਜਾਂ ਰਿਕਵਰੀ ਕੋਡ ਸਾਂਝੇ ਨਾ ਕਰੋ।',
};

const INCOMPLETE_REPLIES = {
  en: 'I could not complete that answer. Please ask one focused cybersecurity question. If an account is at risk, change its password through the official site, sign out other sessions, and enable MFA. Never share OTPs or recovery codes.',
  hi: 'मैं पूरा जवाब तैयार नहीं कर सका। कृपया साइबर सुरक्षा से जुड़ा एक स्पष्ट सवाल पूछें। अगर कोई खाता जोखिम में है, तो आधिकारिक वेबसाइट से पासवर्ड बदलें, बाकी सेशन से साइन आउट करें और MFA चालू करें। OTP या रिकवरी कोड साझा न करें।',
  pa: 'ਮੈਂ ਪੂਰਾ ਜਵਾਬ ਤਿਆਰ ਨਹੀਂ ਕਰ ਸਕਿਆ। ਕਿਰਪਾ ਕਰਕੇ ਸਾਇਬਰ ਸੁਰੱਖਿਆ ਬਾਰੇ ਇੱਕ ਸਪੱਸ਼ਟ ਸਵਾਲ ਪੁੱਛੋ। ਜੇ ਖਾਤਾ ਖਤਰੇ ਵਿੱਚ ਹੈ, ਤਾਂ ਅਧਿਕਾਰਤ ਵੈੱਬਸਾਈਟ ਰਾਹੀਂ ਪਾਸਵਰਡ ਬਦਲੋ, ਹੋਰ ਸੈਸ਼ਨਾਂ ਤੋਂ ਸਾਈਨ ਆਉਟ ਕਰੋ ਅਤੇ MFA ਚਾਲੂ ਕਰੋ। OTP ਜਾਂ ਰਿਕਵਰੀ ਕੋਡ ਸਾਂਝੇ ਨਾ ਕਰੋ।',
};


const FUZZY_CYBER_KEYWORDS = [
  // 1. General cybersecurity
  'cybersecurity', 'cyber security', 'cybercrime', 'cyber crime', 'cyber',
  'security', 'safety', 'internet', 'online', 'digital', 'information security',
  'infosec', 'computer security', 'digital security', 'internet security',
  'network security', 'data security', 'application security', 'web security',
  'mobile security', 'cloud security', 'endpoint security', 'cyber awareness',
  'cyber safety', 'cyber protection', 'cyber hygiene', 'cyber threat',
  'cyber attack', 'cyber risk', 'cyber law', 'cyber ethics', 'digital safety',
  'online safety', 'internet safety', 'security awareness', 'security incident',
  'security breach', 'security vulnerability', 'digital protection',
  'online protection', 'safe browsing', 'digital literacy', 'digital awareness',
  'threat actor', 'attacker', 'hacker', 'hacking', 'hack', 'hacked',
  'ethical hacker', 'black hat', 'white hat', 'grey hat', 'cybercriminal',
  'cybercriminals', 'cyberattack', 'cyberattacks', 'cyberwarfare',
  'cyber espionage', 'cyber terrorism', 'cyberstalking', 'arrest',

  // 2. Phishing, scams and social engineering
  'phishing', 'phish', 'phished', 'spear phishing', 'whaling',
  'clone phishing', 'email phishing', 'sms phishing', 'smishing',
  'voice phishing', 'vishing', 'quishing', 'qr phishing',
  'social engineering', 'pretexting', 'baiting', 'quid pro quo',
  'scam', 'scams', 'scammer', 'scammers', 'fraud', 'fraudster',
  'fraudsters', 'online fraud', 'digital fraud', 'internet fraud',
  'cyber fraud', 'financial fraud', 'identity fraud', 'fake website',
  'fake app', 'fake application', 'fake profile', 'fake account',
  'fake customer care', 'fake customer support', 'fake helpline',
  'fake job', 'job scam', 'employment scam', 'work from home scam',
  'task scam', 'survey scam', 'lottery scam', 'prize scam',
  'giveaway scam', 'reward scam', 'refund scam', 'cashback scam',
  'investment scam', 'trading scam', 'crypto scam', 'cryptocurrency scam',
  'romance scam', 'dating scam', 'matrimonial scam', 'marriage scam',
  'advance fee fraud', 'charity scam', 'donation scam', 'auction scam',
  'shopping scam', 'ecommerce scam', 'marketplace scam', 'seller scam',
  'buyer scam', 'classified scam', 'rental scam', 'property scam',
  'travel scam', 'ticket scam', 'insurance scam', 'loan scam',
  'credit scam', 'debt collection scam', 'tax scam', 'customs scam',
  'courier scam', 'parcel scam', 'delivery scam', 'digital arrest',
  'digital arrest scam', 'virtual arrest', 'police impersonation',
  'impersonation', 'impersonate', 'spoofing', 'caller id spoofing',
  'email spoofing', 'domain spoofing', 'website spoofing',
  'brand impersonation', 'authority impersonation', 'blackmail',
  'extortion', 'sextortion', 'threatening message', 'urgent payment',
  'suspicious offer', 'fraudulent offer', 'fake investment',
  'advance payment', 'payment request', 'money mule', 'mule account',
  'scam call', 'fraud call', 'suspicious call', 'scam message',
  'fraud message', 'suspicious message', 'scam link', 'fraud link',
  'fake police call', 'fake court notice', 'fake legal notice',
  'fake warrant', 'fake arrest warrant', 'fake cbi officer',
  'fake customs officer', 'fake ed officer', 'fake income tax officer',
  'police verification scam', 'government impersonation',

  // 3. Passwords, accounts and authentication
  'password', 'passwords', 'passcode', 'passphrase', 'pin',
  'secret pin', 'otp', 'one time password', 'one-time password',
  'mfa', '2fa', 'two factor authentication', 'multi factor authentication',
  'multifactor authentication', 'authentication', 'authorization',
  'authenticator', 'authenticator app', 'biometric', 'fingerprint',
  'face recognition', 'passkey', 'security key', 'access key',
  'recovery key', 'backup code', 'login', 'log in', 'signin', 'sign in',
  'sign-in', 'logout', 'log out', 'session', 'session hijacking',
  'account security', 'account protection', 'account recovery',
  'account takeover', 'account hacked', 'account compromised',
  'account stolen', 'account locked', 'account disabled',
  'account suspended', 'unauthorized login', 'unauthorised login',
  'unusual login', 'suspicious login', 'login alert', 'login attempt',
  'failed login', 'password reset', 'password change', 'password manager',
  'weak password', 'strong password', 'password reuse', 'password leak',
  'password breach', 'credential', 'credentials', 'credential theft',
  'credential stuffing', 'brute force', 'brute force attack',
  'dictionary attack', 'rainbow table', 'default password',
  'forgot password', 'forgotten password', 'reset password',
  'change password', 'stolen credentials', 'session fixation',
  'session token', 'cookie theft', 'token theft', 'authentication bypass',
  'access control', 'privilege escalation', 'least privilege',
  'single sign on', 'sso', 'oauth', 'openid', 'identity provider',
  'account verification', 'email verification', 'verification',
  'passcode security', 'login security', 'account access',

  // 4. Malware and malicious software
  'malware', 'malicious software', 'virus', 'computer virus', 'worm',
  'computer worm', 'trojan', 'trojan horse', 'ransomware', 'spyware',
  'adware', 'rootkit', 'bootkit', 'keylogger', 'screenlogger',
  'banking trojan', 'remote access trojan', 'rat', 'backdoor',
  'botnet', 'bot', 'zombie computer', 'cryptojacking', 'fileless malware',
  'polymorphic malware', 'wiper malware', 'mobile malware',
  'android malware', 'ios malware', 'mac malware', 'windows malware',
  'malicious apk', 'infected file', 'infected device', 'malicious attachment',
  'malicious download', 'malicious script', 'malicious code', 'payload',
  'dropper', 'loader', 'exploit kit', 'drive by download',
  'drive-by download', 'browser hijacker', 'potentially unwanted program',
  'pup', 'unwanted software', 'fake antivirus', 'rogue security software',
  'file encryption attack', 'ransom demand', 'data encryption malware',
  'malware removal', 'virus removal', 'virus scan', 'malware scan',
  'infected phone', 'infected computer', 'pop up virus', 'virus warning',
  'fake virus alert', 'computer infection', 'malicious program',
  'suspicious software', 'spy app', 'stalkerware', 'mobile spyware',

  // 5. Data breaches, leaks and ransomware
  'data breach', 'data leak', 'data leakage', 'information leak',
  'database leak', 'database breach', 'privacy breach', 'security leak',
  'personal data breach', 'sensitive data', 'exposed data', 'leaked data',
  'stolen data', 'data theft', 'data exfiltration', 'data loss',
  'data exposure', 'confidential information', 'personal information',
  'personally identifiable information', 'pii', 'financial information',
  'medical records', 'customer data', 'employee data', 'database security',
  'database protection', 'data protection', 'data recovery', 'backup',
  'backups', 'disaster recovery', 'ransomware recovery', 'encrypted files',
  'locked files', 'ransom payment', 'double extortion', 'triple extortion',
  'leak site', 'dark web leak', 'breach notification', 'data deletion',
  'secure deletion', 'data wiping', 'data retention', 'file recovery',
  'recover files', 'leaked information', 'exposed database',
  'personal data exposure', 'data privacy breach',

  // 6. Hacking and attack techniques
  'unauthorized access', 'unauthorised access', 'remote access',
  'remote code execution', 'rce', 'command injection', 'code injection',
  'sql injection', 'sqli', 'cross site scripting', 'xss',
  'cross-site scripting', 'stored xss', 'reflected xss', 'dom xss',
  'cross site request forgery', 'csrf', 'xsrf',
  'server side request forgery', 'ssrf', 'xml external entity', 'xxe',
  'directory traversal', 'path traversal', 'file inclusion',
  'local file inclusion', 'remote file inclusion', 'buffer overflow',
  'heap overflow', 'stack overflow', 'memory corruption', 'zero day',
  'zero-day', 'zero day vulnerability', 'exploit', 'exploitation',
  'vulnerability', 'vulnerabilities', 'cve', 'common vulnerabilities',
  'security patch', 'unpatched software', 'patch management',
  'lateral movement', 'persistence', 'defense evasion', 'initial access',
  'command and control', 'c2', 'living off the land',
  'man in the middle', 'mitm', 'machine in the middle', 'replay attack',
  'downgrade attack', 'evil twin', 'rogue access point', 'dns poisoning',
  'dns spoofing', 'arp spoofing', 'ip spoofing', 'tcp hijacking',
  'clickjacking', 'tabnabbing', 'watering hole attack',
  'supply chain attack', 'dependency confusion', 'typosquatting',
  'homograph attack', 'domain squatting', 'subdomain takeover',
  'website defacement', 'website hacked', 'server hacked',
  'website vulnerability', 'api vulnerability', 'api abuse',
  'insecure deserialization', 'insecure direct object reference', 'idor',
  'broken access control', 'security misconfiguration',
  'authentication flaw', 'authorization flaw', 'race condition',
  'denial of service', 'dos attack', 'distributed denial of service',
  'ddos attack', 'traffic flooding', 'resource exhaustion',
  'amplification attack', 'reflection attack', 'network intrusion',
  'intrusion detection', 'intrusion prevention', 'penetration testing',
  'pen testing', 'ethical hacking', 'red team', 'blue team',
  'purple team', 'bug bounty', 'responsible disclosure',
  'responsible vulnerability disclosure', 'attack surface',
  'attack surface management', 'security assessment', 'risk assessment',
  'threat modeling', 'security audit', 'security testing',

  // 7. Mobile, smartphone and app security
  'mobile phone security', 'smartphone security', 'phone security',
  'android security', 'iphone security', 'ios security',
  'mobile app security', 'app permissions', 'application permissions',
  'apk', 'android package', 'sideloading', 'sideloaded app',
  'unknown sources', 'third party app', 'third-party app',
  'unofficial app', 'modified apk', 'mod apk', 'cracked app',
  'malicious app', 'screen sharing', 'remote screen sharing',
  'screen mirroring', 'remote control app', 'remote access app',
  'accessibility permission', 'device administrator', 'admin permission',
  'dangerous permissions', 'microphone permission', 'camera permission',
  'location permission', 'contacts permission', 'sms permission',
  'call forwarding', 'phone cloned', 'device cloned', 'phone stolen',
  'lost phone', 'phone lost', 'phone hacked', 'mobile hacked',
  'camera hacked', 'microphone hacked', 'phone tracking',
  'device tracking', 'find my device', 'remote wipe', 'factory reset',
  'sim security', 'sim swap', 'sim swapping', 'sim cloning',
  'esim fraud', 'sim card fraud', 'duplicate sim', 'sim replacement fraud',
  'clipboard hijacking', 'notification access', 'overlay attack',
  'tapjacking', 'fake system update', 'browser notification scam',
  'malicious notification', 'phone spyware', 'mobile device security',
  'mobile malware removal', 'app security', 'unsafe application',

  // 8. Banking, UPI and financial cybercrime
  'bank fraud', 'banking fraud', 'online banking', 'internet banking',
  'mobile banking', 'bank account hacked', 'bank account compromised',
  'unauthorized transaction', 'unauthorised transaction',
  'fraudulent transaction', 'suspicious transaction', 'unknown transaction',
  'money stolen', 'money deducted', 'money debited', 'unexpected debit',
  'bank otp', 'bank password', 'bank details', 'bank credentials',
  'bank account security', 'atm fraud', 'atm skimming', 'card skimming',
  'card cloning', 'credit card fraud', 'debit card fraud',
  'credit card stolen', 'debit card stolen', 'card details stolen',
  'cvv', 'card pin', 'contactless fraud', 'pos fraud', 'payment fraud',
  'payment gateway fraud', 'payment link', 'payment security',
  'upi', 'upi fraud', 'upi scam', 'upi pin', 'upi id', 'upi collect',
  'upi collect request', 'upi payment', 'upi transaction', 'upi transfer',
  'upi refund', 'upi chargeback', 'upi safety', 'upi security',
  'upi qr code', 'qr code payment', 'bharat qr', 'bhim', 'phonepe',
  'google pay', 'gpay', 'paytm', 'amazon pay', 'imps', 'neft', 'rtgs',
  'aeps', 'aadhaar enabled payment system', 'aadhaar payment fraud',
  'micro atm', 'net banking fraud', 'wallet fraud', 'digital wallet',
  'fake payment screenshot', 'fake payment receipt', 'payment proof',
  'collect request scam', 'request money scam', 'qr code scam',
  'scan to receive money', 'receive money scam', 'refund link',
  'cash on delivery scam', 'cashback fraud', 'merchant fraud',
  'financial phishing', 'bank impersonation', 'upi collect scam',
  'upi qr scam', 'fake upi app', 'fake banking app', 'atm card trapping',
  'card trapping', 'cash withdrawal fraud', 'loan app scam',
  'instant loan scam', 'illegal loan app', 'loan recovery scam',
  'microfinance scam', 'credit score scam', 'credit report scam',
  'kyc fraud', 'kyc update scam', 'kyc verification scam',
  'pan card fraud', 'aadhaar fraud', 'aadhaar card misuse',
  'aadhaar number theft', 'aadhaar otp', 'bank account freeze scam',
  'account blocking scam', 'income tax scam', 'gst scam', 'sebi scam',
  'rbi impersonation', 'investment fraud', 'stock market scam',
  'forex scam', 'ponzi scheme', 'pyramid scheme', 'pump and dump',
  'crypto wallet theft', 'wallet drained', 'private key theft',
  'seed phrase theft', 'cryptocurrency phishing', 'nft scam',
  'digital currency scam', 'money laundering', 'financial cybercrime',
  'unauthorized upi', 'wrong upi transfer', 'upi dispute',
  'chargeback fraud', 'payment reversal scam', 'fake refund',
  'beneficiary fraud', 'bank transfer scam', 'wire transfer fraud',
  'npcI', 'NPCI', 'reserve bank of india', 'national payments corporation',

  // 9. Indian cybercrime reporting and cyber laws
  'cybercrime complaint', 'cyber crime complaint', 'report cybercrime',
  'report cyber crime', 'cybercrime reporting', 'online complaint',
  'file complaint', 'cybercrime portal', 'cyber crime portal',
  'national cybercrime reporting portal', 'cybercrime.gov.in',
  '1930', 'cyber helpline', 'cybercrime helpline', 'cyber police',
  'cyber cell', 'cyber police station', 'cybercrime investigation',
  'cybercrime complaint status', 'financial fraud reporting',
  'report online fraud', 'report banking fraud', 'report upi fraud',
  'report phishing', 'report scam', 'report fake website',
  'report fake profile', 'report cyberbullying', 'report identity theft',
  'report data breach', 'report hacked account', 'evidence collection',
  'digital evidence', 'preserve evidence', 'complaint acknowledgement',
  'complaint number', 'fir', 'first information report', 'police complaint',
  'electronic evidence', 'it act', 'information technology act',
  'information technology act 2000', 'it act 2000',
  'digital personal data protection act', 'dpdp act',
  'data protection law', 'cyber law india', 'cybercrime law',
  'identity theft law', 'online harassment law', 'cyberstalking law',
  'privacy law', 'data breach reporting', 'cert-in', 'cert in',
  'indian computer emergency response team', 'bank ombudsman',
  'consumer protection', 'consumer complaint', 'digital arrest',
  'fake legal notice', 'fake court notice', 'cybercrime prevention',
  'sanchar saathi', 'chakshu portal', 'report suspicious phone call',
  'report suspicious sms', 'suspected fraud communication',

  // 10. Identity theft and privacy
  'identity theft', 'identity fraud', 'identity protection',
  'identity verification', 'identity misuse', 'identity cloning',
  'personal data', 'personal information', 'sensitive information',
  'privacy', 'online privacy', 'data privacy', 'digital privacy',
  'privacy settings', 'privacy policy', 'consent', 'data collection',
  'data sharing', 'data broker', 'tracking', 'online tracking',
  'browser tracking', 'cross site tracking', 'fingerprinting',
  'browser fingerprinting', 'device fingerprinting', 'location tracking',
  'gps tracking', 'doxxing', 'doxing', 'doxxed', 'swatting',
  'stalking', 'online stalking', 'digital stalking',
  'private information leaked', 'address leaked', 'phone number leaked',
  'email leaked', 'personal photos leaked', 'private photos leaked',
  'identity documents', 'passport details', 'driving licence',
  'voter id', 'pan number', 'aadhaar number', 'date of birth',
  'document forgery', 'identity document fraud', 'fake identity',
  'synthetic identity', 'impersonation fraud', 'data minimization',
  'data anonymization', 'pseudonymization', 'right to privacy',
  'consent management', 'location permissions', 'app tracking',
  'website tracking', 'third party cookies', 'third-party cookies',
  'browser cookies', 'clear browsing data', 'private browsing',
  'incognito mode', 'identity security', 'data confidentiality',

  // 11. Email and messaging security
  'email security', 'email hacked', 'hacked email', 'email account',
  'email account hacked', 'email compromise', 'business email compromise',
  'bec', 'email header', 'email authentication', 'spf', 'dkim', 'dmarc',
  'spam', 'junk mail', 'spam email', 'spam message', 'malicious email',
  'suspicious email', 'email attachment', 'email link', 'email scam',
  'email fraud', 'inbox hacked', 'mailbox hacked', 'email recovery',
  'phishing email', 'fake email', 'fake invoice', 'invoice fraud',
  'whatsapp', 'whatsapp security', 'whatsapp hacked', 'whatsapp scam',
  'whatsapp fraud', 'whatsapp account takeover', 'whatsapp web',
  'telegram', 'telegram scam', 'signal app', 'sms', 'text message',
  'sms fraud', 'sms scam', 'smishing attack', 'text phishing',
  'messaging security', 'instant messaging', 'chat security',
  'message interception', 'encrypted messaging', 'end to end encryption',
  'end-to-end encryption', 'e2ee', 'message forwarding', 'fake message',
  'spoofed message', 'verification code scam', 'missed call scam',
  'one ring scam', 'wangiri scam', 'voicemail phishing',
  'qr code phishing', 'malicious qr code', 'suspicious attachment',
  'email spoofing', 'email account recovery', 'email password',

  // 12. Social media security
  'social media security', 'social media privacy', 'social media scam',
  'social media fraud', 'social media hacked', 'social account hacked',
  'instagram hacked', 'instagram scam', 'instagram fraud',
  'facebook hacked', 'facebook scam', 'facebook fraud',
  'facebook marketplace scam', 'whatsapp impersonation', 'telegram hacked',
  'snapchat hacked', 'snapchat scam', 'youtube account hacked',
  'youtube scam', 'twitter hacked', 'x account hacked', 'linkedin scam',
  'linkedin hacked', 'discord scam', 'discord hacked',
  'gaming account hacked', 'fake social profile', 'fake instagram account',
  'fake facebook account', 'fake celebrity account', 'fake influencer',
  'verified badge scam', 'blue tick scam', 'account impersonation',
  'profile cloning', 'social engineering scam', 'friend in need scam',
  'fake emergency message', 'impersonation account', 'account recovery scam',
  'social media blackmail', 'private account security', 'account privacy',
  'two factor social media', 'social media phishing',
  'malicious direct message', 'dm scam', 'fake giveaway',
  'copyright infringement scam', 'account suspension phishing',
  'copyright strike scam', 'fake monetization offer', 'influencer scam',
  'follower scam', 'engagement scam', 'fake followers',
  'credential harvesting', 'social profile security',

  // 13. SIM, telecom and phone-call fraud
  'telecom fraud', 'phone fraud', 'call fraud', 'caller fraud',
  'sim swap fraud', 'sim swap attack', 'sim cloning fraud',
  'mobile number hijacking', 'number porting fraud',
  'unauthorized sim replacement', 'duplicate sim fraud',
  'call forwarding fraud', 'international call fraud',
  'phone number spoofing', 'fake caller id', 'robocall', 'spam call',
  'telemarketing scam', 'automated scam call', 'voice scam',
  'voice cloning scam', 'call center scam', 'fake support number',
  'remote access scam', 'missed call fraud', 'phone tapping',
  'call interception', 'mobile number security', 'telecom identity theft',
  'fake telecom representative', 'mobile connection scam',
  'sim activation fraud', 'port out fraud', 'number hijack',

  // 14. Wi-Fi, networks and internet
  'network', 'wifi', 'wi-fi', 'wireless security', 'public wifi',
  'public wi-fi', 'open wifi', 'open network', 'unsecured wifi',
  'unsecured network', 'wifi hacking', 'wifi password', 'router security',
  'router hacked', 'router password', 'modem security', 'access point',
  'rogue access point', 'evil twin wifi', 'hotspot security',
  'mobile hotspot', 'vpn', 'virtual private network', 'proxy server',
  'tor network', 'dark web', 'deep web', 'ip address', 'mac address',
  'dns', 'domain name system', 'dhcp', 'tcp', 'udp', 'http', 'https',
  'ssl', 'tls', 'certificate', 'digital certificate', 'certificate error',
  'invalid certificate', 'expired certificate', 'encryption', 'decryption',
  'cryptography', 'public key', 'private key', 'symmetric encryption',
  'asymmetric encryption', 'hashing', 'hash function', 'digital signature',
  'certificate authority', 'network monitoring', 'packet sniffing',
  'packet capture', 'port scanning', 'open ports', 'firewall',
  'network firewall', 'web application firewall', 'waf', 'ids', 'ips',
  'intrusion detection system', 'intrusion prevention system',
  'network segmentation', 'zero trust', 'secure dns', 'dns over https',
  'doh', 'dns over tls', 'dot', 'secure connection',
  'unencrypted connection', 'man in the middle attack', 'packet injection',
  'network traffic analysis', 'network vulnerability',
  'internet connection security', 'router firmware', 'network attack',

  // 15. Website, browser and web application security
  'website security', 'web application', 'web app security',
  'website compromised', 'fake domain', 'suspicious domain',
  'malicious domain', 'domain security', 'domain registration fraud',
  'url', 'uniform resource locator', 'suspicious url', 'shortened url',
  'url shortener', 'redirect', 'open redirect', 'link safety',
  'check link', 'verify link', 'unsafe website', 'malicious website',
  'fake login page', 'login page clone', 'website certificate',
  'browser security', 'browser hijacking', 'browser extension',
  'malicious extension', 'unsafe extension', 'browser exploit',
  'browser vulnerability', 'web cache poisoning', 'web cache deception',
  'content security policy', 'csp', 'cors',
  'cross origin resource sharing', 'same origin policy', 'http headers',
  'secure headers', 'hsts', 'http strict transport security',
  'clickjacking attack', 'formjacking', 'web skimming', 'magecart',
  'web shell', 'web server security', 'web hosting security',
  'wordpress security', 'plugin vulnerability', 'theme vulnerability',
  'cms security', 'website backup', 'website malware', 'website scanner',
  'ssl certificate', 'https warning', 'mixed content warning',
  'pharming', 'homograph domain', 'lookalike domain',
  'domain impersonation', 'malicious redirect', 'unsafe link',

  // 16. Cloud, servers, databases and APIs
  'cloud security', 'cloud storage security', 'cloud account hacked',
  'cloud misconfiguration', 'public bucket', 'exposed storage bucket',
  'cloud data leak', 'cloud access control', 'cloud permissions',
  'aws security', 'azure security', 'google cloud security',
  'cloud backup', 'cloud encryption', 'cloud identity',
  'server security', 'server hacked', 'server breach',
  'database security', 'database injection', 'database exposure',
  'database credentials', 'database password', 'api security',
  'api key', 'api key leak', 'exposed api key', 'api authentication',
  'api authorization', 'api token', 'api abuse', 'rate limiting',
  'broken api', 'rest api security', 'graphql security', 'webhook security',
  'secret management', 'secrets management', 'hardcoded secret',
  'hardcoded credentials', 'environment variable leak', 'configuration leak',
  'source code leak', 'git secret', 'github secret', 'repository leak',
  'private repository', 'container security', 'docker security',
  'kubernetes security', 'virtual machine security', 'serverless security',
  'devsecops', 'secure software development', 'secure coding',
  'software supply chain', 'dependency vulnerability',
  'open source vulnerability', 'package vulnerability',
  'software bill of materials', 'sbom', 'dependency scanning',
  'secrets scanning', 'static analysis', 'dynamic analysis',
  'sast', 'dast', 'iast', 'software composition analysis', 'sca',

  // 17. Operating systems and computer protection
  'computer security', 'laptop security', 'desktop security',
  'windows security', 'macos security', 'linux security',
  'operating system security', 'os security', 'system update',
  'software update', 'security update', 'patch update', 'antivirus',
  'anti virus', 'anti-malware', 'malware protection', 'endpoint protection',
  'endpoint detection', 'edr', 'xdr', 'microsoft defender',
  'windows defender', 'firewall settings', 'disk encryption',
  'full disk encryption', 'bitlocker', 'filevault', 'secure boot',
  'trusted platform module', 'tpm', 'bios security', 'uefi security',
  'usb security', 'infected usb', 'malicious usb', 'usb drop attack',
  'autorun malware', 'macro malware', 'office macro', 'remote desktop',
  'rdp security', 'remote desktop protocol', 'ssh security', 'secure shell',
  'administrator account', 'root access', 'system permissions',
  'user permissions', 'least privilege access', 'local administrator',
  'computer infected', 'laptop hacked', 'pc hacked', 'computer hacked',
  'suspicious process', 'unknown process', 'startup malware',
  'scheduled task malware', 'system hardening', 'secure configuration',
  'configuration management', 'vulnerability management', 'asset inventory',

  // 18. Digital forensics and incident response
  'digital forensics', 'computer forensics', 'mobile forensics',
  'network forensics', 'memory forensics', 'disk forensics',
  'incident response', 'cyber incident', 'security incident response',
  'incident handling', 'incident management', 'forensic investigation',
  'forensic evidence', 'digital evidence collection', 'chain of custody',
  'evidence preservation', 'event logs', 'system logs', 'audit logs',
  'security logs', 'log analysis', 'forensic image', 'disk image',
  'memory dump', 'packet analysis', 'timeline analysis', 'malware analysis',
  'sandbox analysis', 'threat hunting', 'threat intelligence', 'ioc',
  'indicators of compromise', 'indicator of compromise',
  'incident containment', 'incident eradication', 'incident recovery',
  'post incident review', 'root cause analysis', 'security alert',
  'false positive', 'false negative', 'security monitoring', 'siem', 'soar',
  'security operations center', 'soc', 'security operations',
  'digital investigation', 'cyber investigation', 'preserve logs',
  'capture screenshot', 'report incident', 'disconnect infected device',
  'isolate infected computer', 'recovery plan', 'business continuity',
  'disaster recovery plan',

  // 19. Cyberbullying, harassment and online abuse
  'cyberbullying', 'cyber bullying', 'online bullying', 'digital bullying',
  'online harassment', 'cyber harassment', 'online abuse', 'digital abuse',
  'online threats', 'death threat', 'online intimidation',
  'revenge porn', 'non consensual intimate images', 'intimate image abuse',
  'image based abuse', 'sexting blackmail', 'sextortion scam',
  'online blackmail', 'morphing', 'photo morphing', 'deepfake abuse',
  'fake nude image', 'impersonation profile', 'fake profile report',
  'online defamation', 'hate speech online', 'trolling',
  'harassment message', 'threatening email', 'abusive messages',
  'unwanted messages', 'online predator', 'grooming',
  'child online safety', 'child exploitation online',
  'child sexual abuse material', 'csam', 'online exploitation',
  'non consensual content', 'privacy violation', 'image removal request',
  'report abusive content', 'block and report',
  'online safety for children', 'digital wellbeing', 'online reputation',
  'reputation damage',

  // 20. AI, deepfakes and emerging threats
  'artificial intelligence security', 'ai security', 'ai cybercrime',
  'ai scam', 'ai fraud', 'ai phishing', 'ai generated phishing',
  'generative ai security', 'large language model security', 'llm security',
  'prompt injection', 'indirect prompt injection', 'jailbreak attack',
  'ai model abuse', 'model poisoning', 'data poisoning',
  'training data poisoning', 'adversarial machine learning',
  'adversarial attack', 'ai hallucination', 'sensitive data exposure ai',
  'deepfake', 'deepfakes', 'deepfake video', 'deepfake audio',
  'deepfake voice', 'voice cloning', 'voice clone scam', 'synthetic media',
  'synthetic identity', 'ai impersonation', 'ai generated scam',
  'fake ai video', 'fake video call', 'fake video conference',
  'executive impersonation', 'ceo fraud', 'virtual kidnapping scam',
  'fake emergency call', 'ai romance scam', 'ai chatbot scam',
  'automated cyberattack', 'autonomous cyberattack',
  'quantum computing security', 'post quantum cryptography',
  'quantum resistant encryption', 'iot security',
  'internet of things security', 'smart home security',
  'smart device security', 'smart tv security', 'wearable security',
  'connected car security', 'vehicle cybersecurity',
  'industrial control system security', 'ics security', 'scada security',
  'critical infrastructure security', 'operational technology security',
  'ot security', 'satellite cybersecurity', 'drone security', '5g security',
  'telecom cybersecurity',

  // 21. Cryptocurrency and blockchain
  'cryptocurrency', 'crypto', 'bitcoin', 'ethereum', 'blockchain',
  'crypto wallet', 'hot wallet', 'cold wallet', 'hardware wallet',
  'seed phrase', 'recovery phrase', 'wallet security',
  'wallet compromise', 'wallet drained', 'crypto theft', 'crypto fraud',
  'crypto phishing', 'crypto investment scam', 'rug pull',
  'pump and dump scam', 'fake token', 'malicious token',
  'smart contract security', 'smart contract exploit',
  'decentralized finance', 'defi', 'decentralized exchange', 'dex',
  'nft', 'non fungible token', 'nft scam', 'airdrop scam',
  'fake airdrop', 'token approval scam', 'wallet drainer',
  'crypto malware', 'exchange hack', 'crypto exchange fraud',
  'staking scam', 'mining scam', 'fake mining platform',
  'web3 security', 'bridge exploit', 'flash loan attack',
  'blockchain exploit', 'private key theft', 'seed phrase theft',

  // 22. Password hygiene, backups and safe online habits
  'safe internet use', 'safe internet practices', 'online precautions',
  'secure browsing', 'secure downloads', 'download safety', 'email safety',
  'social media safety', 'online shopping safety', 'banking safety',
  'mobile safety', 'password hygiene', 'password security',
  'password strength', 'unique password', 'password generator',
  'password vault', 'password manager security', 'two step verification',
  'two-step verification', 'multifactor login', 'backup codes',
  'account recovery options', 'recovery email', 'recovery phone',
  'automatic updates', 'software patching', 'data backup', 'offline backup',
  'encrypted backup', 'cloud backup security', '3-2-1 backup',
  'secure file sharing', 'file encryption', 'secure messaging',
  'device encryption', 'screen lock', 'auto lock', 'lock screen',
  'biometric authentication', 'permission review', 'app permissions review',
  'secure payment', 'safe payment', 'verify before clicking',
  'verify sender', 'verify website', 'check website legitimacy',
  'check url', 'check sender address', 'avoid phishing', 'avoid scams',
  'scam prevention', 'fraud prevention', 'security checklist',
  'cyber awareness training', 'security best practices',
  'digital safety tips', 'online safety tips', 'protect', 'secure',
  'safety tips', 'protection', 'prevent', 'prevention', 'verify',
  'reset', 'recover', 'recovery', 'report', 'suspicious', 'unsafe',
  'compromised', 'steal', 'stolen', 'unauthorized', 'unauthorised',

  // 23. Common user-described cyber problems
  'i got hacked', 'i am hacked', 'my account is hacked',
  'my phone is hacked', 'my computer is hacked', 'my laptop is hacked',
  'my email is hacked', 'my whatsapp is hacked', 'my instagram is hacked',
  'my facebook is hacked', 'my account was stolen',
  'someone hacked my account', 'someone stole my password',
  'someone accessed my account', 'someone logged in',
  'someone is spying on me', 'someone is tracking my phone',
  'someone is using my identity', 'someone cloned my sim',
  'my sim stopped working', 'my phone has a virus',
  'my computer has a virus', 'my files are encrypted',
  'my files are missing', 'my data was leaked',
  'my personal information was leaked', 'my photos were leaked',
  'my account was suspended', 'my account was disabled',
  'i clicked a suspicious link', 'i opened a suspicious link',
  'i downloaded a suspicious file', 'i installed a suspicious app',
  'i shared my otp', 'i shared my password', 'i shared my upi pin',
  'i shared my bank details', 'i gave remote access',
  'i installed anydesk', 'i installed teamviewer',
  'i installed a remote app', 'i sent money to a scammer',
  'money deducted without permission', 'money stolen from bank account',
  'unauthorized money transfer', 'unknown upi transaction',
  'i received a scam call', 'i received a phishing email',
  'i received a suspicious sms', 'i received a fake police call',
  'i received a digital arrest call', 'i am being blackmailed',
  'someone is blackmailing me', 'someone created my fake profile',
  'someone is impersonating me', 'someone is asking for otp',
  'someone asked for my password', 'someone is threatening me online',
  'my account is compromised', 'my data is exposed',
  'my website was hacked', 'my server was hacked',
  'i lost access to my account', 'i cannot access my account',
  'i forgot my password', 'i think i am being scammed',
  'is this a scam', 'is this link safe', 'is this website safe',
  'is this email genuine', 'is this message genuine',
  'is this call genuine', 'is this app safe',
  'is this payment request safe', 'is this qr code safe',
  'how to recover hacked account', 'how to report cybercrime',
  'how to secure my account', 'how to stop online fraud',
  'how to protect my phone', 'how to remove malware',
  'how to report online harassment',

  // 24. Hindi and Hinglish cyber-awareness terms
  'cyber suraksha', 'cyber surakshit', 'online suraksha',
  'internet suraksha', 'digital suraksha', 'cyber jagrukta',
  'cyber apradh', 'cyber apradh report', 'online dhokha',
  'online thagi', 'cyber thagi', 'dhokhadhadi', 'paise ki thagi',
  'otp fraud', 'otp scam', 'otp maangna', 'otp share',
  'password chori', 'account hack', 'account hack ho gaya',
  'phone hack ho gaya', 'mobile hack ho gaya',
  'instagram hack ho gaya', 'whatsapp hack ho gaya',
  'facebook hack ho gaya', 'email hack ho gaya',
  'mera account hack ho gaya', 'mera phone hack ho gaya',
  'mera paisa kat gaya', 'mere account se paise kat gaye',
  'bank se paise kat gaye', 'paise chori ho gaye',
  'upi se paise kat gaye', 'galat transaction', 'fraud transaction',
  'paise wapas', 'paisa wapas kaise milega',
  'cyber complaint kaise kare', 'cybercrime report kaise kare',
  '1930 helpline', 'cyber cell complaint', 'police ke naam par call',
  'fake link', 'suspicious link', 'nakli website', 'nakli app',
  'nakli account', 'social media hack', 'online blackmail',
  'photo leak', 'private photo leak', 'cyber bullying',
  'online pareshan karna', 'identity chori', 'data leak',
  'personal data chori', 'mobile tracking', 'phone spying',
  'virus aa gaya', 'phone mein virus', 'computer mein virus',
  'hacking se bachna', 'fraud se bachna', 'scam se bachna',
  'online surakshit kaise rahein', 'password kaise badlein',
  'account recover kaise karein', 'fraud report kaise karein',
  'upi pin share', 'bank details share', 'screen share scam',
  'kyc scam', 'loan app fraud', 'job scam', 'work from home scam',
  'lottery scam', 'investment fraud', 'crypto scam',
  'fake customer care', 'customer care fraud', 'qr code scam',
  'refund scam', 'call forwarding fraud', 'aadhaar fraud',
  'pan card fraud', 'sim band ho gaya', 'sim achanak band ho gayi',
  'whatsapp par fraud', 'telegram par scam', 'instagram par fraud',
  'facebook par fraud', 'online paisa fraud', 'mobile chori',
  'phone chori', 'account suraksha', 'password suraksha',

  // 25. Security standards, acronyms and frameworks
  'owasp', 'owasp top 10', 'mitre att&ck', 'mitre attack',
  'attack framework', 'nist cybersecurity framework', 'nist csf',
  'iso 27001', 'iso 27002', 'cis controls', 'sans', 'cwe', 'cve',
  'cvss', 'common weakness enumeration',
  'common vulnerabilities and exposures',
  'common vulnerability scoring system', 'soc 2', 'pci dss',
  'gdpr', 'dpdp', 'hipaa', 'ferpa', 'fido2', 'webauthn',
  'ctf', 'capture the flag', 'threat modeling',
  'security architecture', 'secure by design', 'defense in depth',
  'principle of least privilege', 'zero trust architecture',
  'identity and access management', 'iam',
  'privileged access management', 'pam', 'endpoint detection and response',
  'extended detection and response', 'mobile device management', 'mdm',
  'data loss prevention', 'dlp', 'secure development lifecycle', 'sdlc',
  'confidentiality', 'integrity', 'availability', 'non repudiation',
  'non-repudiation', 'risk mitigation', 'security policy',

  // 26. Cybersecurity tools
  'wireshark', 'nmap', 'metasploit', 'burp suite', 'owasp zap',
  'kali linux', 'parrot os', 'autopsy', 'volatility', 'yara rules',
  'sigma rules', 'snort', 'suricata', 'splunk', 'elastic security',
  'wazuh', 'osquery', 'crowdstrike', 'sentinelone',
  'microsoft sentinel', 'security onion', 'clamav', 'virustotal',
  'urlscan', 'any.run', 'hybrid analysis', 'abuseipdb', 'shodan',
  'censys', 'have i been pwned', 'password breach checker',
  'malware sandbox', 'threat intelligence platform',
  'vulnerability scanner', 'web application scanner',
  'dependency scanner', 'container scanner', 'secret scanner',
  'static code analyzer', 'digital forensic tool', 'packet analyzer',

  // 27. Cybersecurity learning and careers
  'cybersecurity career', 'cybersecurity jobs', 'cybersecurity course',
  'cybersecurity certification', 'cybersecurity training',
  'ethical hacking course', 'ethical hacking certification',
  'cybersecurity roadmap', 'learn cybersecurity', 'learn ethical hacking',
  'cybersecurity beginner', 'security analyst', 'soc analyst',
  'penetration tester', 'incident responder', 'threat hunter',
  'security engineer', 'security architect', 'digital forensic analyst',
  'malware analyst', 'security researcher', 'bug bounty hunter',
  'cybersecurity interview', 'security interview questions',
  'cybersecurity project', 'cybersecurity lab',
  'cybersecurity internship', 'cybersecurity exam',
  'security awareness training', 'phishing awareness training',
  'cybersecurity quiz', 'cyber safety quiz', 'cybersecurity basics',
  'networking basics security', 'computer forensics course',
  'information security course', 'cybersecurity concepts',

  // 28. Additional digital and technology security terms
  'digital footprint', 'online reputation', 'digital identity',
  'internet protocol', 'internet of things', 'iot',
  'machine learning security', 'artificial intelligence',
  'cloud computing security', 'virtualization security',
  'containerization security', 'blockchain security',
  'wireless security', 'bluetooth security', 'nfc security',
  'near field communication', 'rfid security', 'gps security',
  'geolocation privacy', 'location data', 'metadata', 'file metadata',
  'document metadata', 'exif data', 'image metadata',
  'secure communication', 'public key infrastructure', 'pki',
  'key management', 'encryption key', 'secure file transfer',
  'sftp', 'ftps', 'file transfer security', 'data classification',
  'data governance', 'data integrity', 'secure connection',
  'digital certificate', 'secure account', 'device protection',
  'online fraud awareness', 'digital fraud awareness',
  'internet fraud prevention', 'cybersecurity guidelines',
  'cybercrime prevention', 'safe internet', 'online security',
  'network protection', 'digital investigation', 'privacy protection',

  // 29. Additional original keywords and common variants
  'passcode', 'passphrase', 'authentication', 'phishing', 'phish',
  'scam', 'fraud', 'hacked', 'hacking', 'hack', 'malware', 'virus',
  'ransomware', 'spyware', 'breach', 'leak', 'identity', 'theft',
  'social', 'engineering', 'sim', 'swap', 'spoofing', 'sextortion',
  'doxxing', 'keylogger', 'firewall', 'antivirus', 'vpn', 'apk',
  'impersonation', 'impersonate', 'remote', 'access', 'screen',
  'sharing', 'investment', 'courier', 'romance', 'transaction',
  'payment', 'login', 'stolen', 'credentials', 'recovery',
  'verification', 'signal', 'suspicious', 'unsafe', 'protect',
  'secure', 'compromised', 'steal', 'recover', 'report', 'verify',
  'reset', 'account', 'email', 'mailbox', 'inbox', 'profile',
  'link', 'website', 'network', 'phone', 'device', 'bank', 'upi',
  'card', 'message', 'file', 'password', 'otp', 'mfa',
  'unauthorized', 'unauthorised', 'online', 'digital', 'internet',
];


function editDistance(left, right, cutoff) {
  if (Math.abs(left.length - right.length) > cutoff) return cutoff + 1;

  let previous = Array.from({ length: right.length + 1 }, (_value, index) => index);
  for (let leftIndex = 1; leftIndex <= left.length; leftIndex += 1) {
    const current = [leftIndex];
    let rowMinimum = leftIndex;

    for (let rightIndex = 1; rightIndex <= right.length; rightIndex += 1) {
      const substitutionCost = left[leftIndex - 1] === right[rightIndex - 1] ? 0 : 1;
      current[rightIndex] = Math.min(
        previous[rightIndex] + 1,
        current[rightIndex - 1] + 1,
        previous[rightIndex - 1] + substitutionCost
      );
      rowMinimum = Math.min(rowMinimum, current[rightIndex]);
    }

    if (rowMinimum > cutoff) return cutoff + 1;
    previous = current;
  }

  return previous[right.length];
}

function normalizeCyberKeywordSpellings(text) {
  return text.replace(/[a-z]{3,}/gi, (word) => {
    const lowerWord = word.toLowerCase();
    let bestMatch = null;
    let bestDistance = Infinity;
    let ambiguous = false;

    for (const keyword of FUZZY_CYBER_KEYWORDS) {
      if (Math.abs(keyword.length - lowerWord.length) > Math.floor(keyword.length * 0.01)) continue;
      const cutoff = Math.max(1, Math.floor(keyword.length * 0.01));
      const distance = editDistance(lowerWord, keyword, cutoff);
      if (distance > cutoff) continue;
      if (distance < bestDistance) {
        bestMatch = keyword;
        bestDistance = distance;
        ambiguous = false;
      } else if (distance === bestDistance) {
        ambiguous = true;
      }
    }

    return bestMatch && bestDistance > 0 && !ambiguous ? bestMatch : word;
  });
}

function containsCyberTopic(text) {
  const spellingTolerantText = normalizeCyberKeywordSpellings(text);
  return CYBER_TOPIC_PATTERNS.some((pattern) => pattern.test(spellingTolerantText));
}

function isGreeting(message) {
  return GREETING_PATTERN.test(message.trim());
}

function isCyberRelated(message, history = []) {
  if (containsCyberTopic(message)) return true;

  const wordCount = message.trim().split(/\s+/).filter(Boolean).length;
  if (wordCount > 12 || !FOLLOW_UP_PATTERN.test(message.trim())) return false;

  const recentCyberContext = history
    .slice(-6)
    .some((item) => item.role === 'user' && containsCyberTopic(item.content));
  return recentCyberContext;
}

function greetingReply(language) {
  return GREETING_REPLIES[language] || GREETING_REPLIES.en;
}

function outOfScopeReply(language) {
  return OUT_OF_SCOPE_REPLIES[language] || OUT_OF_SCOPE_REPLIES.en;
}

function incompleteAnswerReply(message, language) {
  if (ACCOUNT_COMPROMISE_PATTERN.test(message) && ACCOUNT_REFERENCE_PATTERN.test(message)) {
    return COMPROMISED_ACCOUNT_REPLIES[language] || COMPROMISED_ACCOUNT_REPLIES.en;
  }
  return INCOMPLETE_REPLIES[language] || INCOMPLETE_REPLIES.en;
}

module.exports = { greetingReply, incompleteAnswerReply, isCyberRelated, isGreeting, outOfScopeReply };