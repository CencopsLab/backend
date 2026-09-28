const CYBER_TOPIC_PATTERN = /cyber|security|secure|privacy|online safety|internet safety|digital safety|password|passcode|otp|one.time password|mfa|2fa|authenticat|phish|scam|fraud|hack|malware|virus|ransomware|spyware|data breach|data leak|identity theft|account|login|browser|website|web site|url|link|wifi|wi-fi|network|email|e-mail|sms|upi|bank|payment|app|apk|phone|device|social engineering|cybercrime|cyber crime|1930|साइबर|सुरक्षा|ऑनलाइन|इंटरनेट|पासवर्ड|ओटीपी|धोखाधड़ी|ठगी|फ़िशिंग|खाता|लिंक|मोबाइल|ईमेल|एसएमएस|सायबर|ਸੁਰੱਖਿਆ|ਆਨਲਾਈਨ|ਇੰਟਰਨੈੱਟ|ਪਾਸਵਰਡ|ਓਟੀਪੀ|ਧੋਖਾਧੜੀ|ਠੱਗੀ|ਖਾਤਾ|ਲਿੰਕ|ਮੋਬਾਈਲ|ਈਮੇਲ|ਐਸਐਮਐਸ/i;
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

function isGreeting(message) {
  return GREETING_PATTERN.test(message.trim());
}

function isCyberRelated(message, history = []) {
  if (CYBER_TOPIC_PATTERN.test(message)) return true;

  const wordCount = message.trim().split(/\s+/).filter(Boolean).length;
  if (wordCount > 12 || !FOLLOW_UP_PATTERN.test(message.trim())) return false;

  const previousUserMessage = [...history].reverse().find((item) => item.role === 'user');
  return Boolean(previousUserMessage && CYBER_TOPIC_PATTERN.test(previousUserMessage.content));
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