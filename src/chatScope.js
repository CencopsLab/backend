const DIRECT_CYBER_TOPIC_PATTERN = /\b(?:cyber(?:security|crime)?|cyber crime|online safety|internet safety|digital safety|digital arrest|arrest scam|password|passcode|passphrase|otp|one.time password|mfa|2fa|authenticat\w*|phish(?:ing)?|scam|fraud|hack(?:ed|ing)?|malware|virus|ransomware|spyware|data breach|data leak|identity theft|social engineering|sim swap|spoof(?:ing)?|sextortion|doxxing|keylogger|spyware|firewall|antivirus|vpn|apk|android package|1930)\b|https?:\/\/|www\.|साइबर|सुरक्षा|ऑनलाइन|इंटरनेट|डिजिटल अरेस्ट|डिजिटल गिरफ्तारी|साइबर अपराध|साइबर क्राइम|पासवर्ड|ओटीपी|धोखाधड़ी|ठगी|फ़िशिंग|फिशिंग|सिम स्वैप|यूपीआई धोखाधड़ी|सायबर|ਸੁਰੱਖਿਆ|ਆਨਲਾਈਨ|ਇੰਟਰਨੈੱਟ|ਡਿਜੀਟਲ ਅਰੇਸਟ|ਡਿਜੀਟਲ ਗ੍ਰਿਫਤਾਰੀ|ਸਾਇਬਰ ਅਪਰਾਧ|ਪਾਸਵਰਡ|ਓਟੀਪੀ|ਧੋਖਾਧੜੀ|ਠੱਗੀ|ਸਿਮ ਸਵੈਪ|ਯੂਪੀਆਈ ਧੋਖਾਧੜੀ/i;
const SOCIAL_ENGINEERING_PATTERN = /\b(?:impersonat\w*|pretend(?:ed|ing)? to be|fake (?:police|bank|courier|customer support|tech support)|remote access|screen.?sharing|investment scam|job scam|romance scam|parcel scam|courier scam|fake arrest|threaten(?:ed|ing)? to arrest|demand\w* money|unauthori[sz]ed (?:transaction|payment|login|access)|stolen (?:identity|password|credentials)|recovery code|verification code|one.time code|upi pin|card cvv|lost (?:mobile|phone|network|signal|cellular service)|no (?:mobile )?signal|stopped receiving (?:bank )?(?:codes|otps|sms)|sim swap)\b|पुलिस बनकर|बैंक अधिकारी बनकर|पैसे मांग|पैसे माँग|खाता हैक|नकली कॉल|फर्जी कॉल|संदिग्ध लिंक|नकली लिंक|सिग्नल नहीं|नेटवर्क बंद|ओटीपी नहीं आ|ਸਿਮ ਸਵੈਪ|ਸਿਗਨਲ ਨਹੀਂ|ਨੈੱਟਵਰਕ ਬੰਦ|ਓਟੀਪੀ ਨਹੀਂ ਆ/i;
const DIGITAL_OBJECT = '(?:account|email|e-mail|mailbox|inbox|profile|login|password|link|website|web site|url|wifi|wi-fi|network|phone|device|sim|bank|upi|card|payment|transaction|message|email address|apk|app|file|ईमेल|खाता|मोबाइल|फोन|लिंक|वेबसाइट|बैंक|यूपीआई|सिम|एपीके|ऐप|फ़ाइल|ਖਾਤਾ|ਮੋਬਾਈਲ|ਫ਼ੋਨ|ਲਿੰਕ|ਵੈੱਬਸਾਈਟ|ਬੈਂਕ|ਸਿਮ|ਐਪ|ਫ਼ਾਈਲ)';
const SECURITY_ACTION = '(?:hack(?:ed|ing)?|compromis(?:ed|e)|breach(?:ed)?|steal(?:ing)?|stolen|secure|protect|safe|safety|recover|lock(?:ed)?|suspicious|unsafe|phish(?:ing)?|fraud|scam|unauthori[sz]ed|access(?:ed)?|take[n]? over|report|verify|reset|change|share|send|install|माँग|मांग|हैक|चोरी|सुरक्षित|सुरक्षा|संदिग्ध|धोखाधड़ी|ठगी|शक|ਸ਼ੱਕੀ|ਹੈਕ|ਚੋਰੀ|ਸੁਰੱਖਿਅਤ|ਸੁਰੱਖਿਆ|ਧੋਖਾਧੜੀ|ਠੱਗੀ|ਸ਼ੱਕ)';
const SECURITY_CONTEXT_PATTERN = new RegExp(`(?:${DIGITAL_OBJECT}).{0,45}(?:${SECURITY_ACTION})|(?:${SECURITY_ACTION}).{0,45}(?:${DIGITAL_OBJECT})`, 'i');
const CYBER_TOPIC_PATTERNS = [DIRECT_CYBER_TOPIC_PATTERN, SOCIAL_ENGINEERING_PATTERN, SECURITY_CONTEXT_PATTERN];
const FOLLOW_UP_PATTERN = /^(?:and|also|then|so|why|how|what about|can you explain|please explain|tell me more|what should i do|is it|does it|will it|can i|should i|what if|any other|which one|which|that|it|they|them)\b/i;
const GREETING_PATTERN = /^(?:hi+|hello+|hey+|howdy|good morning|good afternoon|good evening|how are you|how's it going|thanks|thank you|bye|goodbye|नमस्ते|नमस्कार|हाय|ਸਤ ਸ੍ਰੀ ਅਕਾਲ|ਸਤਿ ਸ੍ਰੀ ਅਕਾਲ|ਹੈਲੋ|ਧੰਨਵਾਦ)(?:\s+(?:there|cyberrakshak|assistant))?[!.,?\s]*$/i;
const ACCOUNT_COMPROMISE_PATTERN = /\b(?:hack(?:ed)?|compromis(?:ed|e)|taken over|stolen|breached?)\b/i;
const ACCOUNT_REFERENCE_PATTERN = /\b(?:account|email|e-mail|mailbox|inbox|profile)\b/i;

const GREETING_REPLIES = {
  en: 'Hi! I’m CyberRakshak. I can help with cybersecurity and online safety. What would you like to know?',
  hi: 'नमस्ते! मैं CyberRakshak हूँ। मैं साइबर सुरक्षा और ऑनलाइन सुरक्षा में मदद कर सकता हूँ। आप क्या जानना चाहते हैं?',
  pa: 'ਸਤ ਸ੍ਰੀ ਅਕਾਲ! ਮੈਂ CyberRakshak ਹਾਂ। ਮੈਂ ਸਾਇਬਰ ਸੁਰੱਖਿਆ ਅਤੇ ਆਨਲਾਈਨ ਸੁਰੱਖਿਆ ਬਾਰੇ ਮਦਦ ਕਰ ਸਕਦਾ ਹਾਂ। ਤੁਸੀਂ ਕੀ ਜਾਣਨਾ ਚਾਹੁੰਦੇ ਹੋ?',
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

function containsCyberTopic(text) {
  return CYBER_TOPIC_PATTERNS.some((pattern) => pattern.test(text));
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