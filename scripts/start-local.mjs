import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';

const root = path.resolve(import.meta.dirname, '..');
const backend = spawn(process.execPath, ['backend/server.js'], {
  cwd: root,
  env: {
    ...process.env,
    PORT: '5099',
    DEMO_MODE: '1',
    DATA_DIR: path.join(root, 'build', 'preview-data'),
    GATEWAY_PREFIX: '/app/reverse-proxy',
  },
  stdio: 'inherit',
});

const frontend = spawn(process.execPath, [path.join(root, 'node_modules', 'vite', 'bin', 'vite.js'), '--host', '127.0.0.1', '--port', '5178'], { cwd: root, env: process.env, stdio: 'inherit' });

function stop(code = 0) {
  backend.kill('SIGTERM');
  frontend.kill('SIGTERM');
  setTimeout(() => process.exit(code), 350).unref();
}

backend.on('exit', (code) => { if (code && code !== 0) stop(code); });
frontend.on('exit', (code) => { if (code && code !== 0) stop(code); });
process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));
