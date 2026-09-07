// 零依赖静态服务器（UI 验收辅助）：node scripts/serve-static.mjs <port> [dist目录]
// stdout 首行输出 "LISTENING <port>" 供调用方探测就绪。仅绑定 127.0.0.1。
import { createServer } from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';

const [portArg, distArg] = process.argv.slice(2);
const port = Number.parseInt(portArg ?? '0', 10);
const dist = resolve(distArg ?? new URL('../dist', import.meta.url).pathname);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.gz': 'application/octet-stream',
  '.woff2': 'font/woff2',
};

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  let filePath = join(dist, decodeURIComponent(url.pathname));
  if (!existsSync(filePath) || !statSync(filePath).isFile()) {
    filePath = join(dist, 'index.html'); // SPA 兜底
  }
  if (!existsSync(filePath)) {
    res.writeHead(404);
    res.end('not found');
    return;
  }
  const type = MIME[extname(filePath)] ?? 'application/octet-stream';
  res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
  createReadStream(filePath).pipe(res);
});

server.listen(port, '127.0.0.1', () => {
  console.log(`LISTENING ${server.address().port}`);
});
