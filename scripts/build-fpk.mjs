import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = path.resolve(import.meta.dirname, '..');
const packDir = path.join(root, 'App.Native.ReverseProxy');
const serverDir = path.join(packDir, 'app', 'server');
const webDir = path.join(packDir, 'app', 'www');
const webBuild = path.join(root, 'build', 'web');
const releaseDir = path.join(root, 'dist');
const localFnpack = path.join(root, '.tools', 'fnpack', process.platform === 'win32' ? 'fnpack.exe' : 'fnpack');
const fnpackCommand = process.env.FNPACK_PATH || (fs.existsSync(localFnpack) ? localFnpack : 'fnpack');
const releaseVersion = '1.0.3';

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (cause) { throw new Error(`JSON 文件无法解析：${path.relative(root, file)}（${cause.message}）`); }
}

function parseManifest(source, label) {
  const values = new Map();
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (!match) throw new Error(`${label} 行格式无效：${rawLine}`);
    const key = match[1].trim();
    if (values.has(key)) throw new Error(`${label} 包含重复字段：${key}`);
    values.set(key, match[2].trim());
  }
  return values;
}

function readManifest(file) {
  return parseManifest(fs.readFileSync(file, 'utf8'), path.relative(root, file));
}

function readShellAssignment(script, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = script.match(new RegExp(`^${escapedName}="([^"]+)"\\s*$`, 'm'));
  if (!match) throw new Error(`启动脚本缺少 ${name} 的双引号赋值`);
  return match[1];
}

function validatePackageContract() {
  const manifestPath = path.join(packDir, 'manifest');
  const uiConfigPath = path.join(packDir, 'app', 'ui', 'config');
  const privilegePath = path.join(packDir, 'config', 'privilege');
  const resourcePath = path.join(packDir, 'config', 'resource');
  const launcherPath = path.join(packDir, 'cmd', 'main');
  const manifest = readManifest(manifestPath);
  const uiConfig = readJson(uiConfigPath);
  const privilege = readJson(privilegePath);
  const resource = readJson(resourcePath);
  const launcher = fs.readFileSync(launcherPath, 'utf8');
  const backendSource = fs.readFileSync(path.join(root, 'backend', 'server.js'), 'utf8');

  const appName = manifest.get('appname');
  const launchName = manifest.get('desktop_applaunchname');
  if (!appName || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(appName)) {
    throw new Error(`appname 必须是 URL-safe 的小写标识，当前值：${appName || '(空)'}`);
  }
  for (const field of ['version', 'display_name', 'desc', 'maintainer', 'os_min_version', 'desktop_applaunchname']) {
    if (!manifest.get(field)) throw new Error(`manifest 缺少必要字段：${field}`);
  }
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) {
    throw new Error('config/resource 必须是 JSON 对象');
  }
  for (const iconName of ['ICON.PNG', 'ICON_256.PNG']) {
    const iconPath = path.join(packDir, iconName);
    if (!fs.existsSync(iconPath) || !fs.statSync(iconPath).isFile() || fs.statSync(iconPath).size === 0) {
      throw new Error(`应用包图标缺失或为空：${iconName}`);
    }
  }
  const versionSources = [
    ['manifest', manifest.get('version')],
    ['package.json', readJson(path.join(root, 'package.json')).version],
    ['package-lock.json', readJson(path.join(root, 'package-lock.json')).version],
    ['package-lock.json packages[""]', readJson(path.join(root, 'package-lock.json')).packages?.['']?.version],
    ['backend/package.json', readJson(path.join(root, 'backend', 'package.json')).version],
    ['backend/package-lock.json', readJson(path.join(root, 'backend', 'package-lock.json')).version],
    ['backend/package-lock.json packages[""]', readJson(path.join(root, 'backend', 'package-lock.json')).packages?.['']?.version],
    ['backend/server.js APP_VERSION', backendSource.match(/^const APP_VERSION = ['"]([^'"]+)['"];?\s*$/m)?.[1]],
  ];
  const mismatchedVersion = versionSources.find(([, version]) => version !== releaseVersion);
  if (mismatchedVersion) {
    throw new Error(`版本必须统一为 ${releaseVersion}：${mismatchedVersion[0]} 当前为 ${mismatchedVersion[1] || '(空)'}`);
  }
  if (manifest.get('desktop_uidir') !== 'ui') {
    throw new Error(`desktop_uidir 必须指向 app/ui，当前值：${manifest.get('desktop_uidir') || '(空)'}`);
  }
  for (const [field, expected] of [
    ['platform', 'all'],
    ['source', 'thirdparty'],
    ['ctl_stop', 'true'],
    ['checkport', 'false'],
    ['disable_authorization_path', 'true'],
  ]) {
    if (manifest.get(field) !== expected) {
      throw new Error(`manifest.${field} 必须为 ${expected}，当前值：${manifest.get(field) || '(空)'}`);
    }
  }
  const dependencies = (manifest.get('install_dep_apps') || '')
    .split(':')
    .map((dependency) => dependency.split('>')[0].trim())
    .filter(Boolean);
  if (!dependencies.includes('nodejs_v22')) {
    throw new Error('manifest.install_dep_apps 必须包含 nodejs_v22');
  }

  const entries = uiConfig?.['.url'];
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
    throw new Error('app/ui/config 缺少 .url 入口对象');
  }
  const entryIds = Object.keys(entries);
  if (entryIds.length !== 1 || entryIds[0] !== launchName) {
    throw new Error(`desktop_applaunchname 必须与唯一 UI 入口 ID 一致：${launchName || '(空)'}`);
  }
  const entry = entries[launchName];
  const expectedPrefix = `/app/${appName}`;
  if (entry.gatewayPrefix !== expectedPrefix) {
    throw new Error(`gatewayPrefix 必须为 ${expectedPrefix}，当前值：${entry.gatewayPrefix || '(空)'}`);
  }
  const backendPrefix = backendSource.match(/process\.env\.GATEWAY_PREFIX\s*\|\|\s*['"]([^'"]+)['"]/)?.[1];
  const viteSource = fs.readFileSync(path.join(root, 'vite.config.mjs'), 'utf8');
  const viteBase = viteSource.match(/\bbase:\s*['"]([^'"]+)['"]/)?.[1];
  if (backendPrefix !== expectedPrefix || viteBase !== `${expectedPrefix}/`) {
    throw new Error(`后端默认前缀与 Vite base 必须统一为 ${expectedPrefix}`);
  }
  if (entry.url !== `${expectedPrefix}/`) {
    throw new Error(`桌面入口 url 必须为 ${expectedPrefix}/，当前值：${entry.url || '(空)'}`);
  }
  if (entry.type !== 'iframe' || entry.protocol !== '' || Object.hasOwn(entry, 'port')) {
    throw new Error('统一网关桌面入口必须使用 type=iframe、空 protocol，且不能声明 port');
  }
  if (entry.icon !== 'images/icon_{0}.png'
    || !fs.existsSync(path.join(packDir, 'app', 'ui', 'images', 'icon_64.png'))
    || !fs.existsSync(path.join(packDir, 'app', 'ui', 'images', 'icon_256.png'))) {
    throw new Error('桌面入口图标声明或 64/256 像素图标文件不完整');
  }

  const launcherPrefix = readShellAssignment(launcher, 'GATEWAY_PREFIX');
  const launcherSocket = readShellAssignment(launcher, 'SOCKET_PATH');
  const launcherFrontend = readShellAssignment(launcher, 'FRONTEND_DIST');
  if (launcherPrefix !== entry.gatewayPrefix) {
    throw new Error(`启动脚本 GATEWAY_PREFIX 与 UI 网关前缀不一致：${launcherPrefix}`);
  }
  if (!entry.gatewaySocket
    || path.posix.basename(entry.gatewaySocket) !== entry.gatewaySocket
    || !/^[A-Za-z0-9][A-Za-z0-9._-]*\.sock$/.test(entry.gatewaySocket)) {
    throw new Error(`gatewaySocket 必须是安全的 .sock 文件名，当前值：${entry.gatewaySocket || '(空)'}`);
  }
  const expectedSocket = `\${TRIM_APPDEST}/${entry.gatewaySocket}`;
  if (launcherSocket !== expectedSocket) {
    throw new Error(`启动脚本 SOCKET_PATH 与 gatewaySocket 不一致：${launcherSocket}`);
  }
  const expectedFrontend = `\${TRIM_APPDEST}/${path.basename(webDir)}`;
  if (launcherFrontend !== expectedFrontend) {
    throw new Error(`启动脚本 FRONTEND_DIST 必须指向包内 app/${path.basename(webDir)}，当前值：${launcherFrontend}`);
  }
  if (privilege.username !== appName || privilege.groupname !== appName) {
    throw new Error(`权限用户和组必须与 appname 一致：${appName}`);
  }
  if (privilege.defaults?.['run-as'] !== 'package') {
    throw new Error('权限配置必须使用专用应用用户（defaults.run-as=package）');
  }
  if (!Array.isArray(privilege.capabilities)
    || privilege.capabilities.length !== 1
    || privilege.capabilities[0] !== 'CAP_NET_BIND_SERVICE') {
    throw new Error('权限配置只能申明 CAP_NET_BIND_SERVICE 能力');
  }
  if (entry.allUsers !== false || entry.control?.accessPerm !== 'readonly') {
    throw new Error('管理入口必须使用 allUsers=false 且 control.accessPerm=readonly');
  }
  if (/^\s*umask\s+077\s*$/m.test(launcher)) {
    throw new Error('启动脚本不能使用 umask 077，否则统一网关无法访问 Unix Socket');
  }
  if (!launcher.includes('NODE_ENV="production"') || !launcher.includes('DEMO_MODE="0"')) {
    throw new Error('生产启动脚本必须显式设置 NODE_ENV=production 和 DEMO_MODE=0');
  }
  for (const name of fs.readdirSync(path.join(packDir, 'cmd'))) {
    const scriptPath = path.join(packDir, 'cmd', name);
    if (!fs.statSync(scriptPath).isFile()) continue;
    const script = fs.readFileSync(scriptPath, 'utf8');
    if (!script.startsWith('#!/bin/bash\n') || script.includes('\r')) {
      throw new Error(`生命周期脚本必须使用 Bash shebang 和 LF 换行：${path.relative(root, scriptPath)}`);
    }
  }
  return { appName };
}

function assertInside(candidate, parent) {
  const resolved = path.resolve(candidate);
  const base = `${path.resolve(parent)}${path.sep}`;
  if (!resolved.startsWith(base)) throw new Error(`拒绝操作项目外路径：${resolved}`);
}

function resetDirectory(directory) {
  assertInside(directory, packDir);
  fs.rmSync(directory, { recursive: true, force: true });
  fs.mkdirSync(directory, { recursive: true });
}

function run(command, args, cwd = root) {
  let executable = command;
  let commandArgs = args;
  if (command === 'npm') {
    const npmCli = process.env.npm_execpath
      || (process.platform === 'win32'
        ? path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
        : '');
    if (npmCli && fs.existsSync(npmCli)) {
      executable = process.execPath;
      commandArgs = [npmCli, ...args];
    } else if (process.platform === 'win32') {
      throw new Error('无法定位 npm CLI，拒绝通过未转义的 shell 参数执行打包命令');
    }
  }
  execFileSync(executable, commandArgs, { cwd, stdio: 'inherit' });
}

function validatePackageSourceSafety() {
  const allowedRootEntries = new Set([
    'app',
    'cmd',
    'config',
    'wizard',
    'manifest',
    'LICENSE',
    'ICON.PNG',
    'ICON_256.PNG',
  ]);
  const unexpectedRootEntries = fs.readdirSync(packDir)
    .filter((entry) => !allowedRootEntries.has(entry));
  if (unexpectedRootEntries.length) {
    throw new Error(`应用包根目录包含未审核条目：${unexpectedRootEntries.join(', ')}`);
  }
  const appTree = collectTree(path.join(packDir, 'app'));
  const forbidden = [...appTree.files].find((entry) => (
    /^server\/(?:\.data|data)(?:\/|$)/i.test(entry)
    || /(?:^|\/)network_cert_all\.conf$/i.test(entry)
    || /\.(?:key|pem|pfx|p12)$/i.test(entry)
  ));
  if (forbidden) throw new Error(`应用包包含不应发布的运行数据或密钥文件：app/${forbidden}`);
}

const { appName } = validatePackageContract();
if (process.argv.includes('--validate-only')) {
  console.log('FPK 身份、桌面入口与统一网关配置校验通过。');
  process.exit(0);
}
run('npm', ['--prefix', 'backend', 'test']);
run('npm', ['run', 'build']);
resetDirectory(serverDir);
resetDirectory(webDir);
fs.cpSync(webBuild, webDir, { recursive: true });
for (const name of fs.readdirSync(path.join(packDir, 'cmd'))) fs.chmodSync(path.join(packDir, 'cmd', name), 0o755);

for (const entry of ['server.js', 'package.json', 'package-lock.json', 'lib']) {
  fs.cpSync(path.join(root, 'backend', entry), path.join(serverDir, entry), { recursive: true });
}
for (const required of [
  path.join(webDir, 'index.html'),
  path.join(serverDir, 'server.js'),
  path.join(serverDir, 'lib', 'config-store.js'),
    path.join(serverDir, 'lib', 'certificate-parser.js'),
    path.join(serverDir, 'lib', 'proxy-manager.js'),
    path.join(serverDir, 'lib', 'system-certificate-store.js'),
  ]) {
  if (!fs.existsSync(required)) throw new Error(`打包文件缺失：${path.relative(root, required)}`);
}
const launcher = fs.readFileSync(path.join(packDir, 'cmd', 'main'), 'utf8');
if (!launcher.includes('FRONTEND_DIST="${TRIM_APPDEST}/www"')) throw new Error('启动脚本未将 FRONTEND_DIST 指向包内 app/www');
run('npm', ['ci', '--omit=dev'], serverDir);

validatePackageContract();
validatePackageSourceSafety();

fs.mkdirSync(releaseDir, { recursive: true });
fs.mkdirSync(path.join(packDir, 'wizard'), { recursive: true });
const probe = spawnSync(fnpackCommand, ['--help'], { encoding: 'utf8' });
const probeOutput = `${probe.stdout || ''}\n${probe.stderr || ''}`;
if (probe.error || probe.status !== 0 || !/\bfnpack\b/i.test(probeOutput)) {
  throw new Error(`fnpack 不可用，无法生成 ${appName}.fpk`);
}
const fnpackVersion = probeOutput.match(/\bVersion\s+([^\s]+)/i)?.[1] || '未知版本';
console.log(`fnpack 版本：${fnpackVersion}`);

const expectedFpkName = `${appName}.fpk`;
const releaseFpk = path.join(releaseDir, expectedFpkName);
const legacyFpkName = 'App.Native.ReverseProxy.fpk';
const archiveDir = path.join(releaseDir, 'archive');
const buildStamp = new Date().toISOString().replace(/[:.]/g, '-');

function archiveFpk(source, archivedName, label) {
  if (!fs.existsSync(source)) return null;
  const stat = fs.statSync(source);
  if (!stat.isFile()) throw new Error(`FPK 路径不是文件：${source}`);
  fs.mkdirSync(archiveDir, { recursive: true });
  const destination = path.join(archiveDir, `${archivedName}-${label}-${buildStamp}.fpk`);
  assertInside(destination, releaseDir);
  if (fs.existsSync(destination)) throw new Error(`归档目标已存在，拒绝覆盖：${destination}`);
  fs.renameSync(source, destination);
  console.log(`已归档 FPK：${destination}`);
  return destination;
}

function normalizeTarEntry(entry) {
  return entry.replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, '');
}

function listTarEntries(archive) {
  const output = execFileSync('tar', ['-tf', archive], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return output.split(/\r?\n/).map(normalizeTarEntry).filter(Boolean);
}

function readTarEntry(archive, entry) {
  return execFileSync('tar', ['-xOf', archive, entry], {
    cwd: root,
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function assertSafeArchivePaths(entries, label) {
  for (const entry of entries) {
    if (entry.includes('\0')
      || entry.startsWith('/')
      || /^[A-Za-z]:/.test(entry)
      || entry.split('/').includes('..')) {
      throw new Error(`${label} 包含不安全路径：${entry}`);
    }
  }
}

function assertSingleArchiveEntry(entries, expected, label) {
  const count = entries.filter((entry) => entry === expected).length;
  if (count !== 1) throw new Error(`${label} 必须且只能包含一个 ${expected}，实际数量：${count}`);
}

function collectTree(directory) {
  const files = new Set();
  const directories = new Set();
  function visit(current) {
    for (const dirent of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, dirent.name);
      const relative = path.relative(directory, absolute).split(path.sep).join('/');
      if (dirent.isSymbolicLink()) {
        const resolvedTarget = fs.realpathSync(absolute);
        const allowedBase = `${path.resolve(directory)}${path.sep}`;
        if (!resolvedTarget.startsWith(allowedBase) || !fs.statSync(absolute).isFile()) {
          throw new Error(`打包源包含越界或非文件符号链接：${path.relative(root, absolute)}`);
        }
        files.add(relative);
      } else if (dirent.isDirectory()) {
        directories.add(relative);
        visit(absolute);
      } else if (dirent.isFile()) {
        files.add(relative);
      } else {
        throw new Error(`打包源包含不支持的文件类型：${path.relative(root, absolute)}`);
      }
    }
  }
  visit(directory);
  return { files, directories };
}

function assertPackedBytes(archive, entry, source) {
  const packed = readTarEntry(archive, entry);
  const expected = fs.readFileSync(source);
  if (!packed.equals(expected)) {
    throw new Error(`包内文件与构建源不一致：${entry}`);
  }
}

function verifyGeneratedFpk(generatedFpk, stagingDir) {
  const outerEntries = listTarEntries(generatedFpk);
  assertSafeArchivePaths(outerEntries, expectedFpkName);
  const requiredOuterFiles = [
    'app.tgz',
    'manifest',
    'LICENSE',
    'ICON.PNG',
    'ICON_256.PNG',
    'cmd/main',
    'cmd/install_init',
    'cmd/install_callback',
    'cmd/upgrade_init',
    'cmd/upgrade_callback',
    'cmd/uninstall_init',
    'cmd/uninstall_callback',
    'config/privilege',
    'config/resource',
  ];
  for (const entry of requiredOuterFiles) assertSingleArchiveEntry(outerEntries, entry, expectedFpkName);
  assertSingleArchiveEntry(outerEntries, 'wizard', expectedFpkName);

  const manifestSource = readTarEntry(generatedFpk, 'manifest').toString('utf8');
  const packagedManifest = parseManifest(manifestSource, `${expectedFpkName} 内 manifest`);
  const sourceManifest = readManifest(path.join(packDir, 'manifest'));
  for (const [field, value] of sourceManifest) {
    if (packagedManifest.get(field) !== value) {
      throw new Error(`FPK manifest.${field} 与构建源不一致`);
    }
  }
  const unexpectedManifestFields = [...packagedManifest.keys()]
    .filter((field) => field !== 'checksum' && !sourceManifest.has(field));
  if (unexpectedManifestFields.length) {
    throw new Error(`FPK manifest 出现意外字段：${unexpectedManifestFields.join(', ')}`);
  }
  const packagedAppName = packagedManifest.get('appname');
  const packagedVersion = packagedManifest.get('version');
  if (packagedAppName !== appName || packagedVersion !== releaseVersion) {
    throw new Error(`FPK manifest 身份不符：appname=${packagedAppName || '(空)'}，version=${packagedVersion || '(空)'}；期望 appname=${appName}，version=${releaseVersion}`);
  }

  const appArchiveBytes = readTarEntry(generatedFpk, 'app.tgz');
  const appChecksum = createHash('md5').update(appArchiveBytes).digest('hex');
  if ((packagedManifest.get('checksum') || '').toLowerCase() !== appChecksum) {
    throw new Error('FPK manifest.checksum 与 app.tgz 内容不一致');
  }
  const nestedArchive = path.join(stagingDir, 'verified-app.tgz');
  fs.writeFileSync(nestedArchive, appArchiveBytes, { flag: 'wx' });
  const innerEntries = listTarEntries(nestedArchive);
  assertSafeArchivePaths(innerEntries, `${expectedFpkName} 内 app.tgz`);

  // fnpack intentionally embeds config/ both in the outer FPK and at the
  // root of app.tgz. Treat that documented build output as source-backed
  // content while still rejecting every other unexpected inner entry.
  const sourceTree = collectTree(path.join(packDir, 'app'));
  const configTree = collectTree(path.join(packDir, 'config'));
  const expectedInnerFiles = new Set([
    ...sourceTree.files,
    ...[...configTree.files].map((entry) => `config/${entry}`),
  ]);
  const expectedInnerDirectories = new Set([
    ...sourceTree.directories,
    'config',
    ...[...configTree.directories].map((entry) => `config/${entry}`),
  ]);
  for (const sourceFile of expectedInnerFiles) {
    assertSingleArchiveEntry(innerEntries, sourceFile, `${expectedFpkName} 内 app.tgz`);
  }
  for (const innerEntry of innerEntries) {
    if (!expectedInnerFiles.has(innerEntry) && !expectedInnerDirectories.has(innerEntry)) {
      throw new Error(`app.tgz 出现构建源之外的条目：${innerEntry}`);
    }
  }

  const criticalOuterFiles = requiredOuterFiles.filter((entry) => entry !== 'app.tgz' && entry !== 'manifest');
  for (const entry of criticalOuterFiles) {
    assertPackedBytes(generatedFpk, entry, path.join(packDir, entry));
  }
  for (const entry of [
    'server/server.js',
    'server/package.json',
    'server/package-lock.json',
    'server/lib/certificate-parser.js',
    'server/lib/config-store.js',
    'server/lib/proxy-manager.js',
    'server/lib/system-certificate-store.js',
    'ui/config',
    'ui/images/icon_64.png',
    'ui/images/icon_256.png',
    'www/index.html',
  ]) {
    assertPackedBytes(nestedArchive, entry, path.join(packDir, 'app', entry));
  }
  for (const entry of configTree.files) {
    assertPackedBytes(nestedArchive, `config/${entry}`, path.join(packDir, 'config', entry));
  }
}

const stagingDir = fs.mkdtempSync(path.join(releaseDir, '.fnpack-'));
assertInside(stagingDir, releaseDir);
const generatedFpk = path.join(stagingDir, expectedFpkName);
try {
  execFileSync(fnpackCommand, ['build', '--directory', packDir], { cwd: stagingDir, stdio: 'inherit' });
  if (!fs.existsSync(generatedFpk) || !fs.statSync(generatedFpk).isFile() || fs.statSync(generatedFpk).size === 0) {
    throw new Error(`fnpack 未在隔离目录生成预期产物：${generatedFpk}`);
  }
  verifyGeneratedFpk(generatedFpk, stagingDir);

  archiveFpk(path.join(root, expectedFpkName), appName, 'project-root');
  archiveFpk(path.join(root, legacyFpkName), 'App.Native.ReverseProxy', 'project-root');
  archiveFpk(path.join(releaseDir, legacyFpkName), 'App.Native.ReverseProxy', 'dist');
  const previousRelease = archiveFpk(releaseFpk, appName, 'previous');
  try {
    fs.renameSync(generatedFpk, releaseFpk);
  } catch (promotionError) {
    if (previousRelease && !fs.existsSync(releaseFpk) && fs.existsSync(previousRelease)) {
      try {
        fs.renameSync(previousRelease, releaseFpk);
      } catch (restoreError) {
        throw new Error(`新 FPK 发布失败：${promotionError.message}；旧包恢复也失败：${restoreError.message}`);
      }
      throw new Error(`新 FPK 发布失败，旧包已恢复：${promotionError.message}`);
    }
    throw new Error(`新 FPK 发布失败：${promotionError.message}`);
  }
  if (!fs.existsSync(releaseFpk) || fs.statSync(releaseFpk).size === 0) {
    throw new Error(`FPK 产物发布失败：${releaseFpk}`);
  }
  console.log(`FPK 输出：${releaseFpk}`);
} finally {
  try {
    assertInside(stagingDir, releaseDir);
    fs.rmSync(stagingDir, { recursive: true, force: true });
  } catch (cleanupError) {
    console.warn(`警告：无法清理 FPK 暂存目录 ${stagingDir}：${cleanupError.message}`);
  }
}
