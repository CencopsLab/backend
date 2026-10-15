const { randomInt } = require('node:crypto');
const { STORY_CONTEXTS, TRANSLATIONS } = require('./quizTranslations');

const QUESTION_COUNT = 10;
const SCAM_TYPES = {
  link: {
    label: 'Suspicious links and phishing',
    contexts: [
      'a student checking a scholarship update',
      'a parent tracking a delivery',
      'a shop owner reviewing a payment alert',
      'a traveller checking a booking',
      'a job seeker reading an application update',
      'a pensioner checking a bank notification',
      'a freelancer reviewing an invoice',
      'a resident checking an electricity notice',
      'a customer looking for a refund',
      'a new employee reading an account alert',
    ],
    scenarios: [
      'a text says a parcel is held and links to a lookalike delivery website that asks for a small release fee',
      'a bank warning says the account will be blocked today unless the recipient signs in through a shortened link',
      'a message promises a prize and asks the recipient to enter card details on an unfamiliar website',
      'a payment request opens a page whose address misspells the name of a familiar payment service',
      'an electricity alert threatens disconnection and links to a page asking for an OTP',
      'a job offer arrives through a link that asks for a registration fee before an interview',
      'a social media message says an account is suspended and asks the recipient to verify a password',
      'a QR code on an unexpected notice opens a page asking the recipient to sign in to a bank',
      'a refund message directs the recipient to a non-official page to enter a card number and CVV',
      'a familiar contact sends an unexpected shortened link with no explanation',
    ],
    correctAnswers: [
      'Open the organization’s official app, or type its known website address yourself.',
      'Verify the alert through contact details you find independently, not through the message.',
      'Check the destination with the organization using a trusted channel before proceeding.',
      'Reach the service directly from a saved bookmark or official app rather than following the message.',
    ],
    distractors: [
      'Open the link because the message uses the organization’s logo.',
      'Enter details quickly, then change the password if anything seems wrong.',
      'Forward the link to friends so they can check whether it works.',
    ],
    explanation: 'A convincing message or encrypted connection does not prove who controls a website. Verify through a separate, trusted route.',
  },
  email: {
    label: 'Email and account scams',
    contexts: [
      'a student checking a scholarship email',
      'a parent reviewing a school notice',
      'a shop owner receiving a supplier invoice',
      'a traveller reading a booking change',
      'a job seeker opening a recruiter message',
      'a pensioner reading a bank alert',
      'a freelancer checking a client request',
      'a resident reviewing a tax notice',
      'a customer reading a refund email',
      'a new employee receiving an IT warning',
    ],
    scenarios: [
      'the sender address differs from the company name by one extra letter and the email asks for a password reset',
      'an email claims a bank account is frozen and asks the recipient to reply with an OTP',
      'a supplier unexpectedly changes bank details and demands an urgent transfer',
      'a recruiter asks for identity documents and an upfront placement fee before a verified interview',
      'a delivery email attaches an unexpected file and urges the recipient to enable macros',
      'an invoice uses an unfamiliar sender domain and pressures the recipient to pay immediately',
      'an email says a cloud account will be deleted unless the recipient signs in through its link',
      'a refund message asks for full card details and a one-time code by reply',
      'a manager sends an unusual confidential payment request from a personal email account',
      'a message threatens legal action unless the recipient opens an unexpected attachment',
    ],
    correctAnswers: [
      'Confirm the request by calling a known official contact; never send an OTP or password by email.',
      'Check the sender using contact details from the organization’s official site, not the email.',
      'Report the message through the provider and verify any payment or account request independently.',
      'Ask the sender through a separate trusted channel before opening an attachment or paying.',
    ],
    distractors: [
      'Reply with the requested code because the email knows the recipient’s name.',
      'Pay first to prevent a deadline, then confirm the sender afterward.',
      'Open the attachment on a phone because phones cannot get malware.',
    ],
    explanation: 'An email address or domain check cannot authenticate the sender. Verify sensitive requests independently; never share OTPs or passwords.',
  },
  sms: {
    label: 'SMS and text-message scams',
    contexts: [
      'a student waiting for an exam result',
      'a parent expecting a school update',
      'a shop owner receiving a payment alert',
      'a traveller waiting for a ticket message',
      'a job seeker receiving an offer by text',
      'a pensioner checking a bank SMS',
      'a freelancer receiving a client message',
      'a resident reading a utility alert',
      'a customer waiting for a refund',
      'a new employee receiving an account notice',
    ],
    scenarios: [
      'a text from a familiar-looking sender ID says the bank account will be blocked and asks for an OTP',
      'a delivery text includes a tracking link and asks for a small fee to release an unexpected parcel',
      'a message claims a payment was received and asks the recipient to scan a QR code to collect money',
      'an SMS says a mobile connection will stop unless the recipient shares identity documents on a link',
      'a text promises a government benefit and requests bank details to release it',
      'a message from a known contact asks for an urgent transfer to a new UPI ID',
      'a promotional text says a prize is reserved but asks for a processing fee',
      'a utility alert threatens disconnection and requests payment through an unfamiliar link',
      'a text says a SIM will be deactivated and asks the recipient to install a support app',
      'an SMS sender name looks official, but the message asks for a password and card PIN',
    ],
    correctAnswers: [
      'Check the claim in the organization’s official app or by calling its published number.',
      'Keep OTPs, PINs, and passwords private; confirm the message through a trusted channel.',
      'Contact the organization using a number you find independently before taking action.',
      'Open the official service directly and inspect the account there instead of using the message.',
    ],
    distractors: [
      'Trust the sender name because official-looking headers cannot be copied.',
      'Share the OTP if the sender knows the recipient’s name.',
      'Pay the small fee first because it is probably refundable.',
    ],
    explanation: 'A sender header lookup uses offline reference data and cannot verify the live sender, message, route, or template. Treat message content separately.',
  },
  phone: {
    label: 'Impersonation and phone-call scams',
    contexts: [
      'a student contacted about a scholarship',
      'a parent called about a delivery',
      'a shop owner receiving a payment call',
      'a traveller contacted about a booking',
      'a job seeker called by a recruiter',
      'a pensioner receiving a bank call',
      'a freelancer contacted by a client',
      'a resident called about a utility account',
      'a customer contacted about a refund',
      'a new employee receiving an IT support call',
    ],
    scenarios: [
      'a caller claiming to be police says there is an arrest warrant and demands an immediate transfer to avoid custody',
      'a caller claiming to be bank support asks the recipient to read out an OTP to stop a transaction',
      'a caller claiming to be a courier says a parcel contains illegal items and demands a fee to close a case',
      'a caller claiming to be technical support asks for remote access to fix an account problem',
      'a caller claiming to be a government official threatens benefit cancellation unless a fee is paid',
      'a caller claiming to be a relative in an emergency asks for money to a new account',
      'a recruiter promises a guaranteed job but asks for a deposit and identity documents on the call',
      'a caller says a SIM is being duplicated and asks for account credentials to secure it',
      'a caller promises a refund and asks the recipient to approve a collect request in a payment app',
      'a caller demands secrecy and says not to contact the bank or family while sending money',
    ],
    correctAnswers: [
      'Hang up and call back using the organization’s official number found independently.',
      'Pause the request and verify the caller through a separate, trusted contact channel.',
      'Call the bank, agency, or relative using a number already known to you.',
      'Ask for no codes or transfers; independently contact the organization before acting.',
    ],
    distractors: [
      'Stay on the call and follow instructions because the caller sounds authoritative.',
      'Share the OTP but do not share the account password.',
      'Transfer a small amount first to prove the caller is genuine.',
    ],
    explanation: 'A valid-looking phone number does not identify its current owner or prove a caller’s claims. Call back using a number found independently.',
  },
  file: {
    label: 'Suspicious apps and files',
    contexts: [
      'a student downloading a study guide',
      'a parent receiving a school app',
      'a shop owner installing a payment tool',
      'a traveller downloading a ticket file',
      'a job seeker receiving an application form',
      'a pensioner offered a banking app',
      'a freelancer opening a client document',
      'a resident receiving a utility app',
      'a customer offered a refund app',
      'a new employee asked to install a work tool',
    ],
    scenarios: [
      'a message urges the recipient to sideload an APK that requests SMS and accessibility access',
      'an app outside the official store asks for notification access to reveal an unexpected reward',
      'a supposed bank update arrives as an APK attachment rather than through the official app store',
      'a PDF invoice unexpectedly asks the recipient to install an extra viewer from an unknown link',
      'a ZIP archive from an unknown sender contains an executable described as a receipt',
      'a support agent asks the recipient to install a remote-control app to fix a payment issue',
      'a familiar contact sends an app file with no explanation and asks the recipient to disable security settings',
      'an app requests SMS access even though its claimed purpose does not need text messages',
      'a file-sharing page asks the recipient to install a certificate or profile to view a document',
      'a file scan cannot inspect the contents of the selected PDF or image',
    ],
    correctAnswers: [
      'Get the app from its official store or verified publisher and review each requested permission.',
      'Confirm the file with the publisher through its official website before opening or installing it.',
      'Use a trusted app-store listing and grant only permissions needed for the app’s stated purpose.',
      'Ask the sender to confirm through another channel, then obtain the file from an official source.',
    ],
    distractors: [
      'Install it because the file name includes the organization’s name.',
      'Grant every permission so the app can finish its security check.',
      'Disable device protection temporarily if installation is blocked.',
    ],
    explanation: 'This scanner meaningfully inspects APK manifest permissions only; other file types are not antivirus-scanned. Permission results do not prove malware or safety.',
  },
  qr: {
    label: 'QR code and digital wallet scams',
    contexts: [
      'a student paying at a campus canteen',
      'a parent paying for parking',
      'a shop owner setting up a payment counter',
      'a traveller scanning a menu QR code',
      'a job seeker paying a registration fee',
      'a pensioner scanning a bill payment code',
      'a freelancer receiving a client deposit',
      'a resident paying utility bills via a flyer',
      'a customer claiming a store discount',
      'a new employee setting up an office wallet',
    ],
    scenarios: [
      'a QR code stuck on a public parking meter opens an unofficial payment page belonging to a stranger',
      'a QR code scanned to connect to a free Wi-Fi network at a cafe steals login credentials',
      'a promotional sticker scan subtracts money from the wallet instead of giving a reward',
      'a payment app request sent as a QR code turns out to be a collect request asking for a UPI PIN',
      'a QR code on a rental apartment advertisement demands an advance token deposit',
      'a cashback QR code from an unknown source asks for a PIN to release funds',
      'a fraudulent QR code is pasted over the authentic payment sticker at an EV charging station',
      'scanning a restaurant digital menu downloads an unverified third-party APK file',
      'a street vendor payment sticker has been swapped with a scammer’s QR code',
      'a code scanned for a free coupon requests full digital wallet access permission',
    ],
    correctAnswers: [
      'Check the recipient and amount in your payment app before authorizing a transaction.',
      'Use the merchant’s verified payment details; entering a PIN authorizes money to leave your account.',
      'Type the official website yourself and approve a payment only when you initiated it.',
      'Confirm the payment recipient with the merchant before scanning or approving anything.',
    ],
    distractors: [
      'Scan any visible QR code because they are completely secure by default.',
      'Approve collect requests immediately if a stranger claims to be sending you money.',
      'Trust stickers pasted over payment counters without checking.',
    ],
    explanation: 'QR codes can seamlessly redirect browsers to malicious phishing pages or initiate unauthorized collect requests. Always verify recipient details before approving transactions.',
  },
  crypto: {
    label: 'Cryptocurrency and investment scams',
    contexts: [
      'a student exploring digital assets',
      'a parent looking for side income',
      'a shop owner checking investment platforms',
      'a traveller researching exchange apps',
      'a job seeker looking at online earnings',
      'a pensioner reviewing retirement funds',
      'a freelancer looking to hold stablecoins',
      'a resident checking high-yield pools',
      'a customer joining a trading group',
      'a new employee setting up a crypto wallet',
    ],
    scenarios: [
      'a social media ad promises guaranteed daily returns on a new cryptocurrency token',
      'an acquaintance met online suggests depositing funds into an unfamiliar trading platform',
      'a fake trading app shows massive profits but blocks any withdrawal requests',
      'a deepfake video of a tech leader promotes a live cryptocurrency giveaway scam',
      'a cloud mining service demands an extra activation fee after collecting initial funds',
      'a messaging group promotes a pump-and-dump scheme for a low-liquidity token',
      'a self-proclaimed financial advisor asks for funds to be sent directly to a personal wallet',
      'an initial coin offering (ICO) website disappears entirely shortly after collecting deposits',
      'a high-frequency trading bot requires transferring crypto assets to an unverified address',
      'a support agent asks for a private key or seed phrase to "verify" a wallet connection',
    ],
    correctAnswers: [
      'Research the platform independently and never disclose a wallet seed phrase or private key.',
      'Treat guaranteed returns as a warning and verify the provider with the relevant regulator.',
      'Keep your wallet credentials private and consult an independently verified financial source.',
      'Check withdrawal terms and the platform’s registration before risking any money.',
    ],
    distractors: [
      'Transfer funds immediately to secure a limited-time high return slot.',
      'Share your wallet seed phrase if support asks for it during verification.',
      'Trust social media ads featuring celebrity endorsements for crypto projects.',
    ],
    explanation: 'Cryptocurrency transactions are irreversible. High-yield promises and requests for private keys or seed phrases are definitive indicators of fraud.',
  },
};

const SCENARIO_CONTEXTS = [
  'while checking an account alert',
  'after receiving an unexpected deadline',
  'while using a shared family device',
  'after asking customer support for help',
  'during a busy workday',
  'while travelling away from home',
  'after seeing a familiar logo',
  'when a message arrives from an unknown sender',
  'while trying to recover access to an account',
  'after a recent purchase',
];

const COMMON_DISTRACTORS = {
  en: [
    'Act immediately because the request claims to be urgent.',
    'Use the contact details supplied in the message to verify who sent it.',
    'Share the requested code or payment first, then check the account.',
    'Trust the request because it uses a familiar name or logo.',
  ],
  hi: [
    'अनुरोध को तुरंत मानें क्योंकि उसमें जल्दी करने का दबाव है।',
    'भेजने वाले की पुष्टि के लिए संदेश में दिए संपर्क विवरण का उपयोग करें।',
    'पहले माँगा गया कोड या भुगतान साझा करें, फिर खाते की जाँच करें।',
    'अनुरोध पर भरोसा करें क्योंकि इसमें जाना-पहचाना नाम या लोगो है।',
  ],
  pa: [
    'ਬੇਨਤੀ ਤੇ ਤੁਰੰਤ ਕਾਰਵਾਈ ਕਰੋ ਕਿਉਂਕਿ ਇਸ ਵਿੱਚ ਜਲਦੀ ਕਰਨ ਦਾ ਦਬਾਅ ਹੈ।',
    'ਭੇਜਣ ਵਾਲੇ ਦੀ ਪੁਸ਼ਟੀ ਲਈ ਸੁਨੇਹੇ ਵਿੱਚ ਦਿੱਤੇ ਸੰਪਰਕ ਵੇਰਵੇ ਵਰਤੋ।',
    'ਪਹਿਲਾਂ ਮੰਗਿਆ ਕੋਡ ਜਾਂ ਭੁਗਤਾਨ ਸਾਂਝਾ ਕਰੋ, ਫਿਰ ਖਾਤੇ ਦੀ ਜਾਂਚ ਕਰੋ।',
    'ਬੇਨਤੀ ਤੇ ਭਰੋਸਾ ਕਰੋ ਕਿਉਂਕਿ ਇਸ ਵਿੱਚ ਜਾਣਿਆ-ਪਛਾਣਿਆ ਨਾਮ ਜਾਂ ਲੋਗੋ ਹੈ।',
  ],
};

const LOCALIZED_CORRECT_ANSWERS = {
  hi: [
    'संदेश में दिए लिंक या नंबर के बजाय सेवा का आधिकारिक ऐप या वेबसाइट स्वयं खोलें।',
    'अनुरोध पर कार्रवाई करने से पहले संगठन से स्वतंत्र रूप से पुष्टि करें।',
    'OTP, PIN, पासवर्ड और भुगतान विवरण साझा न करें; आधिकारिक माध्यम से जाँचें।',
    'पहचान और भुगतान की जानकारी को भरोसेमंद आधिकारिक स्रोत से सत्यापित करें।',
  ],
  pa: [
    'ਸੁਨੇਹੇ ਵਿੱਚ ਦਿੱਤੇ ਲਿੰਕ ਜਾਂ ਨੰਬਰ ਦੀ ਬਜਾਏ ਸੇਵਾ ਦੀ ਅਧਿਕਾਰਤ ਐਪ ਜਾਂ ਵੈੱਬਸਾਈਟ ਖੁਦ ਖੋਲ੍ਹੋ।',
    'ਬੇਨਤੀ ਤੇ ਕਾਰਵਾਈ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਸੰਸਥਾ ਨਾਲ ਵੱਖਰੇ ਤੌਰ ਤੇ ਪੁਸ਼ਟੀ ਕਰੋ।',
    'OTP, PIN, ਪਾਸਵਰਡ ਅਤੇ ਭੁਗਤਾਨ ਵੇਰਵੇ ਸਾਂਝੇ ਨਾ ਕਰੋ; ਅਧਿਕਾਰਤ ਤਰੀਕੇ ਨਾਲ ਜਾਂਚੋ।',
    'ਪਛਾਣ ਅਤੇ ਭੁਗਤਾਨ ਦੀ ਜਾਣਕਾਰੀ ਨੂੰ ਭਰੋਸੇਯੋਗ ਅਧਿਕਾਰਤ ਸਰੋਤ ਤੋਂ ਤਸਦੀਕ ਕਰੋ।',
  ],
};

function makeOptions(correctAnswer, distractors, answerIndex, scenarioIndex, contextIndex) {
  const combinations = [];
  for (let first = 0; first < distractors.length - 2; first += 1) {
    for (let second = first + 1; second < distractors.length - 1; second += 1) {
      for (let third = second + 1; third < distractors.length; third += 1) {
        combinations.push([distractors[first], distractors[second], distractors[third]]);
      }
    }
  }
  const combinationIndex = (
    scenarioIndex * 37
    + contextIndex * 19
    + scenarioIndex * contextIndex * 31
    + scenarioIndex ** 2 * 11
    + contextIndex ** 2 * 7
  ) % combinations.length;
  const options = [correctAnswer, ...combinations[combinationIndex]];
  const orderedOptions = options.slice(1);
  orderedOptions.splice(answerIndex, 0, correctAnswer);
  return orderedOptions;
}

function withCaseContext(options, scenario, scenarios, context, language) {
  const words = scenario.trim().split(/\s+/);
  const contextLabel = context.trim().split(/\s+/).slice(0, 2).join(' ');
  let labelLength = 2;
  while (
    labelLength < words.length
    && new Set(scenarios.map((item) => item.trim().split(/\s+/).slice(0, labelLength).join(' '))).size < scenarios.length
  ) {
    labelLength += 1;
  }
  const caseLabel = words.slice(0, labelLength).join(' ');
  const prefix = language === 'hi'
    ? `“${caseLabel}” वाले मामले में (${contextLabel}): `
    : language === 'pa'
      ? `“${caseLabel}” ਵਾਲੇ ਮਾਮਲੇ ਵਿੱਚ (${contextLabel}): `
      : `In the “${caseLabel}” case (${contextLabel}): `;
  return options.map((option) => `${prefix}${option}`);
}

function makeInventory(type, definition) {
  return definition.scenarios.flatMap((scenario, scenarioIndex) =>
    definition.contexts.slice(0, 5).map((context, contextIndex) => {
      const answerIndex = (scenarioIndex * 3 + contextIndex) % 4;
      const answerVariantIndex = (scenarioIndex + contextIndex) % definition.correctAnswers.length;
      const distractors = [...definition.distractors, ...COMMON_DISTRACTORS.en];
      const scenarioContext = SCENARIO_CONTEXTS[(scenarioIndex + contextIndex) % SCENARIO_CONTEXTS.length];
      const story = `${context} receives a message or request that ${scenario}. This happens ${scenarioContext}.`;
      return {
        id: `${type}-${scenarioIndex + 1}-${contextIndex + 1}`,
        type,
        story,
        question: 'What is the safest next step?',
        options: withCaseContext(
          makeOptions(
            definition.correctAnswers[answerVariantIndex],
            distractors,
            answerIndex,
            scenarioIndex,
            contextIndex
          ),
          scenario,
          definition.scenarios,
          context,
          'en'
        ),
        answerIndex,
        answerVariantIndex,
        explanation: definition.explanation,
      };
    })
  );
}

const INVENTORY = Object.fromEntries(
  Object.entries(SCAM_TYPES).map(([type, definition]) => [type, makeInventory(type, definition)])
);

function localizedQuestion(question, language) {
  if (language === 'en' || !TRANSLATIONS[language]) {
    const {
      answerIndex: _answerIndex,
      answerVariantIndex: _answerVariantIndex,
      explanation: _explanation,
      ...publicQuestion
    } = question;
    return publicQuestion;
  }
  const translation = TRANSLATIONS[language][question.type];
  const [, scenarioNumber, contextNumber] = question.id.split('-');
  const scenarioIndex = Number(scenarioNumber) - 1;
  const contextIndex = Number(contextNumber) - 1;
  const context = STORY_CONTEXTS[language][contextIndex];
  const scenario = translation.scenarios[scenarioIndex];
  const correctAnswers = LOCALIZED_CORRECT_ANSWERS[language];
  const distractors = [...translation.distractors, ...COMMON_DISTRACTORS[language]];
  const localizedOptions = withCaseContext(
    makeOptions(
      correctAnswers[question.answerVariantIndex],
      distractors,
      question.answerIndex,
      scenarioIndex,
      contextIndex
    ),
    scenario,
    translation.scenarios.slice(0, 10),
    context,
    language
  );
  return {
    id: question.id,
    type: question.type,
    story: `${context}: ${scenario}`,
    question: language === 'hi' ? 'सबसे सुरक्षित अगला कदम क्या है?' : 'ਸਭ ਤੋਂ ਸੁਰੱਖਿਅਤ ਅਗਲਾ ਕਦਮ ਕੀ ਹੈ?',
    options: localizedOptions,
  };
}

function sampleQuestions(type, language = 'en', random = randomInt) {
  if (!Object.hasOwn(INVENTORY, type)) return null;
  const questions = INVENTORY[type];
  const pool = questions.slice();
  const selected = [];
  for (let index = 0; index < QUESTION_COUNT; index += 1) {
    const selectedIndex = random(index, pool.length);
    [pool[index], pool[selectedIndex]] = [pool[selectedIndex], pool[index]];
    selected.push(localizedQuestion(pool[index], language));
  }
  return selected;
}

function checkAnswer(type, questionId, answerIndex, language = 'en') {
  const question = Object.hasOwn(INVENTORY, type)
    ? INVENTORY[type].find((item) => item.id === questionId)
    : undefined;
  if (!question) return null;
  const translation = TRANSLATIONS[language]?.[type];
  const correctAnswer = language === 'en' || !translation
    ? question.options[question.answerIndex]
    : localizedQuestion(question, language).options[question.answerIndex];
  return {
    correct: answerIndex === question.answerIndex,
    correctAnswer,
    explanation: translation?.explanation ?? question.explanation,
  };
}

module.exports = { INVENTORY, QUESTION_COUNT, SCAM_TYPES, checkAnswer, localizedQuestion, sampleQuestions };