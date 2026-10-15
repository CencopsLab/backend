const { rateLimit } = require('express-rate-limit');

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function createRateLimiters(env = process.env) {
  const windowMs = positiveInteger(env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000);
  const uploadWindowMs = positiveInteger(env.APK_UPLOAD_RATE_LIMIT_WINDOW_MS, windowMs);

  function createLimiter(scope, limit, message, limiterWindowMs = windowMs) {
    return rateLimit({
      windowMs: limiterWindowMs,
      limit,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      message: {
        code: 'RATE_LIMITED',
        scope,
        limit,
        windowMs: limiterWindowMs,
        error: message,
      },
    });
  }

  return {
    api: createLimiter('api', positiveInteger(env.API_RATE_LIMIT_MAX, 300), 'Too many API requests. Please try again later.'),
    chat: createLimiter('chat', positiveInteger(env.CHAT_RATE_LIMIT_MAX, 20), 'Too many chat requests. Please try again later.'),
    translate: createLimiter('translate', positiveInteger(env.CHAT_TRANSLATE_RATE_LIMIT_MAX, 30), 'Too many translation requests. Please try again later.'),
    scan: createLimiter('scan', positiveInteger(env.SCAN_RATE_LIMIT_MAX, 60), 'Too many scan requests. Please try again later.'),
    apkUpload: createLimiter(
      'apk_upload',
      positiveInteger(env.APK_UPLOAD_RATE_LIMIT_MAX, 5),
      'Too many APK uploads. Please try again later.',
      uploadWindowMs,
    ),
  };
}

module.exports = { createRateLimiters };