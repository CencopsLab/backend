const yauzl = require('yauzl');

const NO_INDEX = 0xffffffff;
const RES_XML_TYPE = 0x0003;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_XML_START_NAMESPACE_TYPE = 0x0100;
const RES_XML_END_NAMESPACE_TYPE = 0x0101;
const RES_XML_START_ELEMENT_TYPE = 0x0102;
const RES_XML_END_ELEMENT_TYPE = 0x0103;
const RES_XML_CDATA_TYPE = 0x0104;
const MAX_MANIFEST_SIZE = 16 * 1024 * 1024;

function readUInt8(data, position) {
  if (position < 0 || position >= data.length) {
    throw new Error(`Android manifest data out of bounds at offset ${position}`);
  }
  return data.readUInt8(position);
}

function readUInt16(data, position) {
  if (position < 0 || position + 2 > data.length) {
    throw new Error(`Android manifest data out of bounds at offset ${position}`);
  }
  return data.readUInt16LE(position);
}

function readUInt32(data, position) {
  if (position < 0 || position + 4 > data.length) {
    throw new Error(`Android manifest data out of bounds at offset ${position}`);
  }
  return data.readUInt32LE(position);
}

function assertRange(data, position, size) {
  if (!Number.isSafeInteger(position) || !Number.isSafeInteger(size)
    || position < 0 || size < 0 || position + size > data.length) {
    throw new Error(`Android manifest data out of bounds: offset=${position}, size=${size}, length=${data.length}`);
  }
}

function readLength8(data, position) {
  let length = readUInt8(data, position);
  position += 1;
  if (length & 0x80) {
    length = ((length & 0x7f) << 8) | readUInt8(data, position);
    position += 1;
  }
  return [length, position];
}

function readLength16(data, position) {
  let length = readUInt16(data, position);
  position += 2;
  if (length & 0x8000) {
    length = ((length & 0x7fff) << 16) | readUInt16(data, position);
    position += 2;
  }
  return [length, position];
}

function readUtf8String(data, position, end) {
  const [characterLength, afterCharacterLength] = readLength8(data, position);
  const [byteLength, contentPosition] = readLength8(data, afterCharacterLength);
  assertRange(data, contentPosition, byteLength + 1);
  if (contentPosition + byteLength + 1 > end) {
    throw new Error('Android manifest UTF-8 string exceeds its string pool');
  }
  const value = data.toString('utf8', contentPosition, contentPosition + byteLength);
  if (value.length !== characterLength) {
    throw new Error('Invalid Android manifest UTF-8 string length');
  }
  return value;
}

function readUtf16String(data, position, end) {
  const [characterLength, contentPosition] = readLength16(data, position);
  const byteLength = characterLength * 2;
  assertRange(data, contentPosition, byteLength + 2);
  if (contentPosition + byteLength + 2 > end) {
    throw new Error('Android manifest UTF-16 string exceeds its string pool');
  }
  return data.toString('utf16le', contentPosition, contentPosition + byteLength);
}

function parseStringPool(data, chunkPosition, chunkSize, headerSize) {
  if (headerSize < 28 || chunkSize < headerSize) {
    throw new Error('Invalid Android manifest string pool header');
  }

  const chunkEnd = chunkPosition + chunkSize;
  const stringCount = readUInt32(data, chunkPosition + 8);
  const styleCount = readUInt32(data, chunkPosition + 12);
  const flags = readUInt32(data, chunkPosition + 16);
  const stringsStart = readUInt32(data, chunkPosition + 20);
  const stylesStart = readUInt32(data, chunkPosition + 24);
  const offsetsPosition = chunkPosition + headerSize;
  const offsetCount = stringCount + styleCount;

  if (!Number.isSafeInteger(offsetCount) || offsetCount * 4 > chunkEnd - offsetsPosition) {
    throw new Error('Invalid Android manifest string pool offsets');
  }
  if (stringsStart < headerSize + offsetCount * 4 || stringsStart > chunkSize) {
    throw new Error('Invalid Android manifest string pool data offset');
  }
  if (stylesStart !== 0 && (stylesStart < stringsStart || stylesStart > chunkSize)) {
    throw new Error('Invalid Android manifest string pool style offset');
  }

  const stringsEnd = stylesStart === 0 ? chunkEnd : chunkPosition + stylesStart;
  const strings = [];
  const isUtf8 = (flags & 0x100) !== 0;
  for (let index = 0; index < stringCount; index += 1) {
    const stringOffset = readUInt32(data, offsetsPosition + index * 4);
    const position = chunkPosition + stringsStart + stringOffset;
    if (position < chunkPosition + stringsStart || position >= stringsEnd) {
      throw new Error(`Invalid Android manifest string offset ${stringOffset}`);
    }
    strings.push(isUtf8
      ? readUtf8String(data, position, stringsEnd)
      : readUtf16String(data, position, stringsEnd));
  }
  return strings;
}

function getString(strings, index) {
  if (index === NO_INDEX) return null;
  return index < strings.length ? strings[index] : `<string:${index}>`;
}

function decodeTypedValue(data, position, strings) {
  assertRange(data, position, 8);
  const type = readUInt8(data, position + 3);
  const value = readUInt32(data, position + 4);
  switch (type) {
    case 0x00: return null;
    case 0x01: return `@0x${value.toString(16).padStart(8, '0')}`;
    case 0x02: return `?0x${value.toString(16).padStart(8, '0')}`;
    case 0x03: return getString(strings, value);
    case 0x04: {
      const floatBytes = Buffer.allocUnsafe(4);
      floatBytes.writeUInt32LE(value, 0);
      return String(floatBytes.readFloatLE(0));
    }
    case 0x05:
    case 0x06:
    case 0x11:
      return `0x${value.toString(16).padStart(8, '0')}`;
    case 0x10:
      return String(value);
    case 0x12:
      return value === 0 ? 'false' : 'true';
    default:
      return `0x${value.toString(16).padStart(8, '0')}`;
  }
}

function findPermissionAttribute(attributes, name) {
  return attributes.find((attribute) => attribute.name === name)?.value;
}

function findDeclaredPermission(attributes) {
  const namedPermission = findPermissionAttribute(attributes, 'name');
  if (typeof namedPermission === 'string' && namedPermission) return namedPermission;
  return attributes.find((attribute) => (
    typeof attribute.value === 'string'
    && /^android\.permission\.[A-Z0-9_]+$/.test(attribute.value)
  ))?.value;
}

function addPermission(permissions, permission) {
  if (typeof permission === 'string' && permission && !permissions.includes(permission)) {
    permissions.push(permission);
  }
}

function parseBinaryManifestPermissions(data) {
  if (!Buffer.isBuffer(data) || data.length < 8) {
    throw new Error('Invalid AndroidManifest.xml');
  }
  if (readUInt16(data, 0) !== RES_XML_TYPE) {
    throw new Error('AndroidManifest.xml is not compiled Android binary XML');
  }

  const headerSize = readUInt16(data, 2);
  const declaredSize = readUInt32(data, 4);
  if (headerSize < 8 || declaredSize < headerSize || declaredSize > data.length) {
    throw new Error('Invalid Android manifest XML header');
  }

  const endOfManifest = declaredSize;
  let position = headerSize;
  let strings = [];
  const permissions = [];
  const namespaceStack = [];

  while (position + 8 <= endOfManifest) {
    const chunkType = readUInt16(data, position);
    const chunkHeaderSize = readUInt16(data, position + 2);
    const chunkSize = readUInt32(data, position + 4);
    if (chunkHeaderSize < 8 || chunkSize < chunkHeaderSize || position + chunkSize > endOfManifest) {
      throw new Error(`Invalid Android manifest chunk at offset ${position}`);
    }

    if (chunkType === RES_STRING_POOL_TYPE) {
      strings = parseStringPool(data, position, chunkSize, chunkHeaderSize);
    } else if (chunkType === RES_XML_START_NAMESPACE_TYPE) {
      if (chunkSize < 24) throw new Error('Invalid Android manifest namespace chunk');
      namespaceStack.push({
        prefix: getString(strings, readUInt32(data, position + 16)),
        uri: getString(strings, readUInt32(data, position + 20)),
      });
    } else if (chunkType === RES_XML_END_NAMESPACE_TYPE) {
      if (chunkSize < 24) throw new Error('Invalid Android manifest namespace chunk');
      const prefix = getString(strings, readUInt32(data, position + 16));
      const uri = getString(strings, readUInt32(data, position + 20));
      const index = namespaceStack.findLastIndex((namespace) => namespace.prefix === prefix && namespace.uri === uri);
      if (index !== -1) namespaceStack.splice(index, 1);
    } else if (chunkType === RES_XML_START_ELEMENT_TYPE) {
      if (chunkSize < 36) throw new Error('Invalid Android manifest start-element chunk');
      const tagName = getString(strings, readUInt32(data, position + 20));
      const attributeStart = readUInt16(data, position + 24);
      const attributeSize = readUInt16(data, position + 26);
      const attributeCount = readUInt16(data, position + 28);
      if (attributeSize < 20) throw new Error('Invalid Android manifest attribute size');

      let attributePosition = position + 16 + attributeStart;
      const attributes = [];
      for (let index = 0; index < attributeCount; index += 1) {
        if (attributePosition + attributeSize > position + chunkSize) {
          throw new Error('Android manifest attribute exceeds its element chunk');
        }
        const name = getString(strings, readUInt32(data, attributePosition + 4));
        const rawValue = readUInt32(data, attributePosition + 8);
        const value = rawValue === NO_INDEX
          ? decodeTypedValue(data, attributePosition + 12, strings)
          : getString(strings, rawValue);
        attributes.push({ name, value });
        attributePosition += attributeSize;
      }

      if (typeof tagName === 'string' && /^uses-permission(?:-sdk-\d+)?$/.test(tagName)) {
        addPermission(permissions, findDeclaredPermission(attributes));
      } else if (tagName === 'service' || tagName === 'receiver') {
        const permission = findPermissionAttribute(attributes, 'permission');
        if (/^android\.permission\.BIND_(ACCESSIBILITY_SERVICE|NOTIFICATION_LISTENER_SERVICE|DEVICE_ADMIN)$/.test(permission || '')) {
          addPermission(permissions, permission);
        }
      }
    } else if (chunkType === RES_XML_END_ELEMENT_TYPE && chunkSize < 24) {
      throw new Error('Invalid Android manifest end-element chunk');
    } else if (chunkType === RES_XML_CDATA_TYPE && chunkSize < 28) {
      throw new Error('Invalid Android manifest CDATA chunk');
    }

    position += chunkSize;
  }

  if (position !== endOfManifest) {
    throw new Error('Incomplete Android manifest chunk data');
  }
  return permissions;
}

function extractManifestPermissions(manifest) {
  const permissions = [];
  const permissionPattern = /<uses-permission(?:-sdk-\d+)?\b([^>]*)>/g;
  let match;
  while ((match = permissionPattern.exec(manifest)) !== null) {
    const name = match[1].match(/\bname="([^"]+)"/)
      || match[1].match(/(?:^|\s)="([^"]+)"/);
    if (name) addPermission(permissions, name[1]);
  }

  const componentPattern = /<(service|receiver)\b([\s\S]*?)>/g;
  while ((match = componentPattern.exec(manifest)) !== null) {
    const componentPermission = match[2].match(/\bpermission="([^"]+)"/);
    if (/^android\.permission\.BIND_(ACCESSIBILITY_SERVICE|NOTIFICATION_LISTENER_SERVICE|DEVICE_ADMIN)$/.test(componentPermission?.[1] || '')) {
      addPermission(permissions, componentPermission[1]);
    }
  }
  return permissions;
}

function createManifestError(message, code) {
  return Object.assign(new Error(message), { code });
}

function encryptedManifestError(cause) {
  const error = createManifestError('The APK manifest is encrypted or its ZIP encryption flag is incorrect.', 'APK_MANIFEST_ENCRYPTED');
  if (cause) error.cause = cause;
  return error;
}

function readManifestFromApk(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true, validateEntrySizes: false }, (archiveError, zipFile) => {
      if (archiveError) {
        reject(new Error(`Could not read APK archive: ${archiveError.message}`, { cause: archiveError }));
        return;
      }

      let settled = false;
      const finishError = (error) => {
        if (settled) return;
        settled = true;
        zipFile.close();
        reject(error);
      };
      zipFile.on('error', finishError);
      zipFile.on('end', () => {
        if (!settled) {
          settled = true;
          reject(createManifestError('The APK has no Android manifest.', 'APK_MANIFEST_MISSING'));
        }
      });
      zipFile.on('entry', (entry) => {
        if (entry.fileName !== 'AndroidManifest.xml') {
          zipFile.readEntry();
          return;
        }
        const encryptionFlagSet = (entry.generalPurposeBitFlag & 0x1) !== 0;
        if (entry.uncompressedSize > MAX_MANIFEST_SIZE) {
          finishError(new Error('Could not read AndroidManifest.xml: manifest exceeds the maximum supported size'));
          return;
        }
        if (!encryptionFlagSet && entry.compressionMethod === 0 && entry.compressedSize !== entry.uncompressedSize) {
          finishError(new Error('Could not read AndroidManifest.xml: stored manifest size does not match its declared size'));
          return;
        }

        // Some APKs mark a readable manifest as encrypted. Let the XML decoder
        // verify the extracted bytes instead of rejecting the ZIP flag alone.
        const readableEntry = encryptionFlagSet
          ? Object.assign(Object.create(Object.getPrototypeOf(entry)), entry, {
            generalPurposeBitFlag: entry.generalPurposeBitFlag & ~0x1,
          })
          : entry;
        zipFile.openReadStream(readableEntry, (streamError, stream) => {
          if (streamError) {
            finishError(encryptionFlagSet
              ? encryptedManifestError(streamError)
              : new Error(`Could not read AndroidManifest.xml: ${streamError.message}`, { cause: streamError }));
            return;
          }
          const chunks = [];
          let totalSize = 0;
          stream.on('data', (chunk) => {
            totalSize += chunk.length;
            if (totalSize > entry.uncompressedSize || totalSize > MAX_MANIFEST_SIZE) {
              stream.destroy();
              finishError(encryptionFlagSet
                ? encryptedManifestError()
                : new Error('Could not read AndroidManifest.xml: manifest exceeds its declared size'));
              return;
            }
            chunks.push(chunk);
          });
          stream.on('error', finishError);
          stream.on('end', () => {
            if (settled) return;
            if (totalSize !== entry.uncompressedSize) {
              finishError(encryptionFlagSet
                ? encryptedManifestError()
                : new Error('Could not read AndroidManifest.xml: manifest size does not match its declaration'));
              return;
            }
            settled = true;
            zipFile.close();
            resolve({ manifest: Buffer.concat(chunks), encryptionFlagSet });
          });
        });
      });
      zipFile.readEntry();
    });
  });
}

async function inspectApkPermissions(buffer) {
  const { manifest, encryptionFlagSet } = await readManifestFromApk(buffer);
  try {
    return parseBinaryManifestPermissions(manifest);
  } catch (error) {
    if (encryptionFlagSet) throw encryptedManifestError(error);
    throw error;
  }
}

module.exports = { extractManifestPermissions, inspectApkPermissions };
