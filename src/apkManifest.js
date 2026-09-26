const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const execFileAsync = promisify(execFile);
const decoderPath = path.join(__dirname, '..', 'tools', 'manifest.py');

async function inspectApkPermissions(buffer) {
  const tempDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'CyberRakshak-apk-'));
  const apkPath = path.join(tempDirectory, 'application.apk');
  const decodedPath = path.join(tempDirectory, 'AndroidManifest_decoded.xml');

  try {
    await fs.writeFile(apkPath, buffer);
    await execFileAsync(process.env.PYTHON_BIN || 'python', [decoderPath, apkPath], {
      timeout: 120000,
      maxBuffer: 2 * 1024 * 1024,
      windowsHide: true,
    });

    const manifest = await fs.readFile(decodedPath, 'utf8');
    const permissions = [];
    const permissionPattern = /<uses-permission(?:-sdk-\d+)?\b[\s\S]*?\bname="([^"]+)"[\s\S]*?>/g;
    let match;
    while ((match = permissionPattern.exec(manifest)) !== null) {
      if (!permissions.includes(match[1])) permissions.push(match[1]);
    }

    return permissions;
  } finally {
    await fs.rm(tempDirectory, { recursive: true, force: true });
  }
}

module.exports = { inspectApkPermissions };
