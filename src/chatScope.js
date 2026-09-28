const CYBER_TOPIC_PATTERN = /cyber|security|secure|privacy|online safety|internet safety|digital safety|password|passcode|otp|one.time password|mfa|2fa|authenticat|phish|scam|fraud|hack|malware|virus|ransomware|spyware|data breach|data leak|identity theft|account|login|browser|website|web site|url|link|wifi|wi-fi|network|email|e-mail|sms|upi|bank|payment|app|apk|phone|device|social engineering|cybercrime|cyber crime|1930|साइबर|सुरक्षा|ऑनलाइन|इंटरनेट|पासवर्ड|ओटीपी|धोखाधड़ी|ठगी|फ़िशिंग|खाता|लिंक|मोबाइल|ईमेल|एसएमएस|सायबर|ਸੁਰੱਖਿਆ|ਆਨਲਾਈਨ|ਇੰਟਰਨੈੱਟ|ਪਾਸਵਰਡ|ਓਟੀਪੀ|ਧੋਖਾਧੜੀ|ਠੱਗੀ|ਖਾਤਾ|ਲਿੰਕ|ਮੋਬਾਈਲ|ਈਮੇਲ|ਐਸਐਮਐਸ/i;
const FOLLOW_UP_PATTERN = /^(?:and|also|then|so|why|how|what about|can you explain|please explain|tell me more|what should i do|is it|does it|will it|can i|should i|what if|any other|which one|which|that|it|they|them)\b/i;
const GREETING_PATTERN = /^(?:hi+|hello+|hey+|howdy|good morning|good afternoon|good evening|how are you|how's it going|thanks|thank you|bye|goodbye|नमस्ते|नमस्कार|हाय|ਸਤ ਸ੍ਰੀ ਅਕਾਲ|ਸਤਿ ਸ੍ਰੀ ਅਕਾਲ|ਹੈਲੋ|ਧੰਨਵਾਦ)(?:\s+(?:there|cyberrakshak|assistant))?[!.,?\s]*$/i;

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

module.exports = { greetingReply, isCyberRelated, isGreeting, outOfScopeReply };