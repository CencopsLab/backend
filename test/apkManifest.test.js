const assert = require('node:assert/strict');
const { deflateRawSync } = require('node:zlib');
const test = require('node:test');
const { inspectApkPermissions } = require('../src/apkManifest');

const NO_INDEX = 0xffffffff;
const ANDROID_NAMESPACE = 'http://schemas.android.com/apk/res/android';

function encodeLength8(length) {
  if (length < 0x80) return Buffer.from([length]);
  return Buffer.from([0x80 | (length >> 8), length & 0xff]);
}

function encodeLength16(length) {
  if (length < 0x8000) {
    const encoded = Buffer.alloc(2);
    encoded.writeUInt16LE(length);
    return encoded;
  }
  const encoded = Buffer.alloc(4);
  encoded.writeUInt16LE(0x8000 | (length >>> 16), 0);
  encoded.writeUInt16LE(length & 0xffff, 2);
  return encoded;
}

function createStringPool(strings, utf8 = true) {
  const encodedStrings = [];
  let offset = 0;
  for (const value of strings) {
    const bytes = Buffer.from(value, utf8 ? 'utf8' : 'utf16le');
    const encoded = utf8
      ? Buffer.concat([
        encodeLength8(value.length),
        encodeLength8(bytes.length),
        bytes,
        Buffer.from([0]),
      ])
      : Buffer.concat([encodeLength16(value.length), bytes, Buffer.from([0, 0])]);
    encodedStrings.push(encoded);
    offset += encoded.length;
  }

  const headerSize = 28;
  const stringsStart = headerSize + strings.length * 4;
  const chunkSize = stringsStart + offset;
  const chunk = Buffer.alloc(chunkSize);
  chunk.writeUInt16LE(0x0001, 0);
  chunk.writeUInt16LE(headerSize, 2);
  chunk.writeUInt32LE(chunkSize, 4);
  chunk.writeUInt32LE(strings.length, 8);
  chunk.writeUInt32LE(0, 12);
  chunk.writeUInt32LE(utf8 ? 0x100 : 0, 16);
  chunk.writeUInt32LE(stringsStart, 20);
  chunk.writeUInt32LE(0, 24);

  let stringOffset = 0;
  strings.forEach((_value, index) => {
    chunk.writeUInt32LE(stringOffset, headerSize + index * 4);
    encodedStrings[index].copy(chunk, stringsStart + stringOffset);
    stringOffset += encodedStrings[index].length;
  });
  return chunk;
}

function createNamespaceChunk(type, prefixIndex, uriIndex) {
  const chunk = Buffer.alloc(24);
  chunk.writeUInt16LE(type, 0);
  chunk.writeUInt16LE(16, 2);
  chunk.writeUInt32LE(chunk.length, 4);
  chunk.writeUInt32LE(NO_INDEX, 12);
  chunk.writeUInt32LE(prefixIndex, 16);
  chunk.writeUInt32LE(uriIndex, 20);
  return chunk;
}

function createStartElementChunk(tagIndex, attributes, strings) {
  const attributeSize = 20;
  const chunk = Buffer.alloc(36 + attributes.length * attributeSize);
  chunk.writeUInt16LE(0x0102, 0);
  chunk.writeUInt16LE(16, 2);
  chunk.writeUInt32LE(chunk.length, 4);
  chunk.writeUInt32LE(NO_INDEX, 12);
  chunk.writeUInt32LE(NO_INDEX, 16);
  chunk.writeUInt32LE(tagIndex, 20);
  chunk.writeUInt16LE(20, 24);
  chunk.writeUInt16LE(attributeSize, 26);
  chunk.writeUInt16LE(attributes.length, 28);

  attributes.forEach((attribute, index) => {
    const position = 36 + index * attributeSize;
    chunk.writeUInt32LE(attribute.namespaceIndex ?? NO_INDEX, position);
    chunk.writeUInt32LE(attribute.nameIndex, position + 4);
    chunk.writeUInt32LE(attribute.rawValueIndex ?? NO_INDEX, position + 8);
    chunk.writeUInt16LE(8, position + 12);
    chunk.writeUInt8(0, position + 14);
    chunk.writeUInt8(attribute.valueType ?? 0x03, position + 15);
    chunk.writeUInt32LE(attribute.valueIndex ?? strings.indexOf(attribute.value), position + 16);
  });
  return chunk;
}

function createEndElementChunk(tagIndex) {
  const chunk = Buffer.alloc(24);
  chunk.writeUInt16LE(0x0103, 0);
  chunk.writeUInt16LE(16, 2);
  chunk.writeUInt32LE(chunk.length, 4);
  chunk.writeUInt32LE(NO_INDEX, 12);
  chunk.writeUInt32LE(NO_INDEX, 16);
  chunk.writeUInt32LE(tagIndex, 20);
  return chunk;
}

function createBinaryManifest(utf8 = true, unreadablePermissionAttributeName = false) {
  const strings = [
    'android',
    ANDROID_NAMESPACE,
    'manifest',
    'uses-permission',
    'uses-permission-sdk-23',
    'service',
    'receiver',
    'name',
    'permission',
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'x'.repeat(130),
  ];
  const index = (value) => strings.indexOf(value);
  const chunks = [
    createStringPool(strings, utf8),
    createNamespaceChunk(0x0100, index('android'), index(ANDROID_NAMESPACE)),
    createStartElementChunk(index('manifest'), [], strings),
    createStartElementChunk(index('uses-permission'), [{
      namespaceIndex: index(ANDROID_NAMESPACE),
      nameIndex: index('name'),
      rawValueIndex: index('android.permission.READ_SMS'),
      valueIndex: NO_INDEX,
    }], strings),
    createEndElementChunk(index('uses-permission')),
    createStartElementChunk(index('uses-permission-sdk-23'), [{
      namespaceIndex: index(ANDROID_NAMESPACE),
      nameIndex: unreadablePermissionAttributeName ? 2176 : index('name'),
      valueType: 0x03,
      valueIndex: index('android.permission.SEND_SMS'),
    }], strings),
    createEndElementChunk(index('uses-permission-sdk-23')),
    createStartElementChunk(index('service'), [{
      namespaceIndex: index(ANDROID_NAMESPACE),
      nameIndex: index('permission'),
      rawValueIndex: index('android.permission.BIND_ACCESSIBILITY_SERVICE'),
      valueIndex: NO_INDEX,
    }], strings),
    createEndElementChunk(index('service')),
    createStartElementChunk(index('receiver'), [{
      namespaceIndex: index(ANDROID_NAMESPACE),
      nameIndex: index('permission'),
      rawValueIndex: index('android.permission.BIND_DEVICE_ADMIN'),
      valueIndex: NO_INDEX,
    }], strings),
    createEndElementChunk(index('receiver')),
    createStartElementChunk(index('uses-permission'), [{
      namespaceIndex: index(ANDROID_NAMESPACE),
      nameIndex: index('name'),
      rawValueIndex: index('x'.repeat(130)),
      valueIndex: NO_INDEX,
    }], strings),
    createEndElementChunk(index('uses-permission')),
    createEndElementChunk(index('manifest')),
    createNamespaceChunk(0x0101, index('android'), index(ANDROID_NAMESPACE)),
  ];
  const content = Buffer.concat(chunks);
  const header = Buffer.alloc(8);
  header.writeUInt16LE(0x0003, 0);
  header.writeUInt16LE(8, 2);
  header.writeUInt32LE(header.length + content.length, 4);
  return Buffer.concat([header, content]);
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createZip(entries) {
  const localFiles = [];
  const centralDirectory = [];
  let localOffset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const content = entry.content ?? Buffer.alloc(0);
    const method = entry.method ?? 8;
    const compressed = method === 8 ? deflateRawSync(content) : content;
    const flags = entry.encrypted ? 1 : 0;
    const checksum = crc32(content);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(flags, 6);
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(content.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    localHeader.writeUInt16LE(0, 28);
    localFiles.push(localHeader, name, compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(flags, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(content.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(localOffset, 42);
    centralDirectory.push(centralHeader, name);
    localOffset += localHeader.length + name.length + compressed.length;
  }

  const central = Buffer.concat(centralDirectory);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localFiles, central, end]);
}

test('extracts APK permissions from UTF-8 binary XML, including typed values and protected components', async () => {
  const apk = createZip([{ name: 'AndroidManifest.xml', content: createBinaryManifest() }]);

  assert.deepEqual(await inspectApkPermissions(apk), [
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'x'.repeat(130),
  ]);
});

test('extracts permissions from UTF-16 binary XML string pools', async () => {
  const apk = createZip([{ name: 'AndroidManifest.xml', content: createBinaryManifest(false) }]);

  assert.deepEqual(await inspectApkPermissions(apk), [
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'x'.repeat(130),
  ]);
});

test('extracts standard permissions when a binary manifest attribute name is unavailable', async () => {
  const apk = createZip([{
    name: 'AndroidManifest.xml',
    content: createBinaryManifest(true, true),
  }]);

  assert.deepEqual(await inspectApkPermissions(apk), [
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'x'.repeat(130),
  ]);
});

test('reports a missing Android manifest with its established error code', async () => {
  const apk = createZip([{ name: 'resources.arsc', content: Buffer.from('resource table') }]);

  await assert.rejects(inspectApkPermissions(apk), { code: 'APK_MANIFEST_MISSING' });
});

test('reports an encrypted Android manifest with its established error code', async () => {
  const apk = createZip([{ name: 'AndroidManifest.xml', content: Buffer.alloc(0), encrypted: true }]);

  await assert.rejects(inspectApkPermissions(apk), { code: 'APK_MANIFEST_ENCRYPTED' });
});

test('extracts a readable stored manifest even when its ZIP encryption flag is set', async () => {
  const apk = createZip([{
    name: 'AndroidManifest.xml',
    content: createBinaryManifest(),
    method: 0,
    encrypted: true,
  }]);

  assert.deepEqual(await inspectApkPermissions(apk), [
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'x'.repeat(130),
  ]);
});

test('reports an unreadable manifest when its ZIP encryption flag is set', async () => {
  const apk = createZip([{
    name: 'AndroidManifest.xml',
    content: Buffer.alloc(572),
    method: 0,
    encrypted: true,
  }]);

  await assert.rejects(inspectApkPermissions(apk), { code: 'APK_MANIFEST_ENCRYPTED' });
});

test('rejects invalid APK archives and malformed binary manifests', async () => {
  await assert.rejects(inspectApkPermissions(Buffer.from('not a zip')), /Could not read APK archive/);
  const apk = createZip([{ name: 'AndroidManifest.xml', content: Buffer.alloc(8) }]);
  await assert.rejects(inspectApkPermissions(apk), /not compiled Android binary XML/);
});
