#!/usr/bin/env node
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const PORT = 3001;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.mjs':  'application/javascript',
  '.css':  'text/css',
  '.wasm': 'application/wasm',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.json': 'application/json',
};

const server = http.createServer((req, res) => {
  let urlPath = req.url.split('?')[0];

  // Root → modal test page
  if (urlPath === '/' || urlPath === '') urlPath = '/test/index.html';

  // Directory → index.html inside it
  if (urlPath.endsWith('/')) urlPath += 'index.html';

  const filePath = path.join(ROOT, urlPath);

  // Prevent directory traversal outside ROOT
  if (!filePath.startsWith(ROOT + path.sep) && filePath !== ROOT) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end(`Not found: ${urlPath}`);
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      'Content-Type': MIME[ext] ?? 'application/octet-stream',
    });
    res.end(data);
  });
});

server.listen(PORT, () => {
  const base = `http://localhost:${PORT}`;
  console.log('');
  console.log('  \x1b[1mQuilibrium SDK — test server\x1b[0m');
  console.log('');
  console.log(`  \x1b[2mPasskeyModal test \x1b[0m  \x1b[36m${base}/test/\x1b[0m`);
  console.log(`  \x1b[2mHook inspector    \x1b[0m  \x1b[36m${base}/test/hook-test.html\x1b[0m`);
  console.log('');
  console.log(`  \x1b[2mServing\x1b[0m             ${ROOT}`);
  console.log('  \x1b[2mCtrl+C to stop\x1b[0m');
  console.log('');
});
