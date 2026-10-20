const dns = require('node:dns').promises;
const http = require('node:http');
const https = require('node:https');
const { BlockList, isIP } = require('node:net');

const LOOKUP_TIMEOUT_MS = 5000;
const MAX_REDIRECTS = 5;
const blockedAddresses = new BlockList();

for (const [subnet, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) {
  blockedAddresses.addSubnet(subnet, prefix, 'ipv4');
}

for (const [subnet, prefix] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48],
  ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7],
  ['fe80::', 10], ['ff00::', 8],
]) {
  blockedAddresses.addSubnet(subnet, prefix, 'ipv6');
}

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

function unavailable(detail, domainExists = null) {
  return { status: 'unavailable', domainExists, httpStatus: null, detail };
}

function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 6 && address.toLowerCase().startsWith('::ffff:')) {
    const mapped = address.toLowerCase().slice('::ffff:'.length);
    const parts = mapped.split(':');
    if (parts.length !== 2 || parts.some((part) => !/^[\da-f]{1,4}$/.test(part))) return false;
    const high = Number.parseInt(parts[0], 16);
    const low = Number.parseInt(parts[1], 16);
    return isPublicAddress(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  return family !== 0 && !blockedAddresses.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

function resolveAddresses(hostname) {
  return dns.lookup(hostname, { all: true, verbatim: true });
}

function requestHeaders(url, addresses, method, timeoutMs) {
  return new Promise((resolve, reject) => {
    const address = addresses[0];
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request({
      protocol: url.protocol,
      hostname: url.hostname.replace(/^\[|\]$/g, ''),
      port: url.port || undefined,
      path: `${url.pathname}${url.search}`,
      method,
      agent: false,
      headers: {
        'User-Agent': 'CyberRakshak-Link-Lookup/1.0',
        ...(method === 'GET' ? { Range: 'bytes=0-0' } : {}),
      },
      lookup: (_hostname, options, callback) => {
        if (options?.all) {
          callback(null, addresses.map(({ address: ip, family: version }) => ({ address: ip, family: version })));
        } else {
          callback(null, address.address, address.family);
        }
      },
    }, (response) => {
      const result = { statusCode: response.statusCode, location: response.headers.location };
      response.destroy();
      resolve(result);
    });

    request.setTimeout(timeoutMs, () => {
      const error = new Error('URL lookup timed out');
      error.code = 'ETIMEDOUT';
      request.destroy(error);
    });
    request.on('error', reject);
    request.end();
  });
}

function resolveWithTimeout(hostname, resolveImpl, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(Object.assign(new Error('DNS lookup timed out'), { code: 'ETIMEDOUT' }));
    }, timeoutMs);
    Promise.resolve()
      .then(() => resolveImpl(hostname))
      .then(
        (addresses) => {
          clearTimeout(timer);
          resolve(addresses);
        },
        (error) => {
          clearTimeout(timer);
          reject(error);
        },
      );
  });
}

async function lookupUrl(value, options = {}) {
  const resolveImpl = options.resolveImpl ?? resolveAddresses;
  const requestImpl = options.requestImpl ?? requestHeaders;
  const timeoutMs = options.timeoutMs ?? LOOKUP_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  const remainingTime = () => Math.max(0, deadline - Date.now());
  let currentUrl;
  let domainExists = null;

  try {
    currentUrl = new URL(value);
  } catch {
    return unavailable('This address could not be checked as a valid URL.');
  }

  const visited = new Set();
  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    if (!['http:', 'https:'].includes(currentUrl.protocol)) {
      return unavailable('Only HTTP and HTTPS addresses can be checked.');
    }
    if (currentUrl.username || currentUrl.password) {
      return unavailable('Addresses containing embedded usernames or passwords are not looked up.');
    }
    const expectedPort = currentUrl.protocol === 'https:' ? '443' : '80';
    if (currentUrl.port && currentUrl.port !== expectedPort) {
      return unavailable('Only standard HTTP and HTTPS ports can be checked.');
    }

    const hostname = currentUrl.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (/(?:^|\.)localhost$|(?:^|\.)(?:local|internal|test|invalid)$/.test(hostname)) {
      return unavailable('Lookup was blocked because the destination is a private or local host.');
    }

    const family = isIP(hostname);
    let addresses;
    if (family) {
      domainExists = null;
      if (!isPublicAddress(hostname)) {
        return unavailable('Lookup was blocked because the destination is a private or local address.');
      }
      addresses = [{ address: hostname, family }];
    } else {
      let resolved;
      try {
        const dnsTimeoutMs = remainingTime();
        if (dnsTimeoutMs === 0) {
          return unavailable('The destination lookup timed out before the link could be verified.');
        }
        resolved = await resolveWithTimeout(hostname, resolveImpl, dnsTimeoutMs);
      } catch (error) {
        if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
          return {
            status: 'not_found',
            domainExists: false,
            httpStatus: null,
            detail: 'The domain name could not be found in public DNS.',
          };
        }
        return unavailable(error.code === 'ETIMEDOUT'
          ? 'The domain lookup timed out before the destination could be verified.'
          : 'The destination could not be reached or its address could not be resolved.');
      }

      if (!Array.isArray(resolved) || resolved.length === 0) {
        return {
          status: 'not_found',
          domainExists: false,
          httpStatus: null,
          detail: 'The domain name could not be found in public DNS.',
        };
      }
      domainExists = true;
      if (resolved.some(({ address: ip }) => !isPublicAddress(ip))) {
        return unavailable('Lookup was blocked because the destination resolves to a private or local address.', true);
      }
      addresses = resolved;
    }

    const target = currentUrl.href;
    if (visited.has(target)) return unavailable('A redirect loop prevented the destination from being verified.');
    visited.add(target);

    let response;
    try {
      const requestTimeoutMs = remainingTime();
      if (requestTimeoutMs === 0) {
        return unavailable('The destination lookup timed out before the link could be verified.');
      }
      response = await requestImpl(currentUrl, addresses, 'HEAD', requestTimeoutMs);
      if ([405, 501].includes(response.statusCode)) {
        const fallbackTimeoutMs = remainingTime();
        if (fallbackTimeoutMs === 0) {
          return unavailable('The destination lookup timed out before the link could be verified.');
        }
        response = await requestImpl(currentUrl, addresses, 'GET', fallbackTimeoutMs);
      }
    } catch (error) {
      return unavailable(error.code === 'ETIMEDOUT'
        ? 'The destination did not respond before the lookup timed out.'
        : 'The destination could not be reached.', domainExists);
    }

    if (REDIRECT_CODES.has(response.statusCode) && response.location) {
      if (redirectCount === MAX_REDIRECTS) {
        return unavailable('Too many redirects prevented the destination from being verified.');
      }
      try {
        currentUrl = new URL(response.location, currentUrl);
      } catch {
        return unavailable('The destination returned an invalid redirect and could not be verified.');
      }
      continue;
    }

    if ([404, 410].includes(response.statusCode)) {
      return {
        status: 'not_found',
        domainExists: family ? null : true,
        httpStatus: response.statusCode,
        detail: 'The domain exists, but the requested page could not be found.',
      };
    }

    if (Number.isInteger(response.statusCode) && response.statusCode >= 200 && response.statusCode < 400) {
      return {
        status: 'reachable',
        domainExists: family ? null : true,
        httpStatus: response.statusCode,
        detail: 'The destination responded. This confirms reachability only, not safety.',
      };
    }

    return {
      status: 'unavailable',
      domainExists: family ? null : true,
      httpStatus: Number.isInteger(response.statusCode) ? response.statusCode : null,
      detail: response.statusCode
        ? 'The domain exists, but link availability could not be confirmed.'
        : 'The destination did not provide a verifiable HTTP response.',
    };
  }

  return unavailable('The destination could not be verified.');
}

module.exports = { lookupUrl };
