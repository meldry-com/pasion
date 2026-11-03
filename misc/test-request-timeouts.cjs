// Run after `dx build -p pasion-frontend --release`.
// Install Playwright in an ignored tools directory and expose it with NODE_PATH:
// npm install --prefix target/request-timeout-tools playwright
// npx --prefix target/request-timeout-tools playwright install chromium
// $env:NODE_PATH = "$PWD/target/request-timeout-tools/node_modules"
// node misc/test-request-timeouts.cjs [path/to/web/public]
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

const assets = path.resolve(process.argv[2] || 'target/dx/pasion-frontend/release/web/public');
const providers = { providers: [], password_login_enabled: true, password_registration_enabled: false };
const viewer = {
  viewer: { __typename: 'User', id: 'test-user', username: 'test', matrix: { mxid: '@test:example.org', display_name: 'Test' } },
  viewer_session: { __typename: 'Anonymous', id: 'test-session' },
  site_config: {},
};
let active;
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname.startsWith('/api/v1/')) {
    const endpoint = pathname.slice('/api/v1'.length);
    res.setHeader('Content-Type', 'application/json');
    if (active && endpoint === active.endpoint && !active.recovered) {
      active.requests++;
      active.started ??= Date.now();
      const scenario = active;
      res.on('close', () => { if (!res.writableFinished) scenario.aborted++; });
      if (active.mode !== 'headers') {
        res.writeHead(active.mode === 'error-body' ? 503 : 200);
        res.write('{'); // Headers arrive, but the JSON body never completes.
      }
      return;
    }
    const payload = endpoint === '/auth/providers' ? providers
      : endpoint === '/viewer' ? viewer
      : endpoint === '/viewer/preferences' ? { available_channels: [], preferences: [] }
      : {};
    res.end(JSON.stringify(payload));
    return;
  }
  try {
    let filename = path.resolve(assets, `.${decodeURIComponent(pathname)}`);
    if (!filename.startsWith(assets + path.sep)) throw new Error('invalid asset path');
    if (!path.extname(filename)) filename = path.join(assets, 'index.html');
    const bytes = await fs.readFile(filename);
    const mime = { '.html': 'text/html', '.js': 'application/javascript', '.wasm': 'application/wasm', '.css': 'text/css' };
    res.setHeader('Content-Type', mime[path.extname(filename)] || 'application/octet-stream');
    res.end(bytes);
  } catch {
    res.writeHead(404).end();
  }
});

(async () => {
  await fs.access(path.join(assets, 'index.html'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true });
  try {
    for (const scenario of [
      { endpoint: '/auth/providers', page: '/login', mode: 'headers', seconds: 5, retry: true },
      { endpoint: '/auth/providers', page: '/login', mode: 'body', seconds: 5, retry: true },
      { endpoint: '/auth/providers', page: '/login', mode: 'error-body', seconds: 5, retry: true },
      { endpoint: '/viewer', page: '/notifications', mode: 'headers', seconds: 5, retry: true },
      { endpoint: '/viewer', page: '/notifications', mode: 'body', seconds: 5, retry: true },
      { endpoint: '/viewer/preferences', page: '/notifications', mode: 'headers', seconds: 15 },
    ]) {
      active = { ...scenario, started: null, requests: 0, aborted: 0, recovered: false };
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(origin + scenario.page);
      const alert = page.locator('.alert-critical').first();
      await alert.waitFor({ timeout: (scenario.seconds + 8) * 1000 });
      assert.ok(active.started, 'target API request was made');
      const elapsed = Date.now() - active.started;
      assert.ok(elapsed >= (scenario.seconds - 1) * 1000 && elapsed < (scenario.seconds + 5) * 1000, `unexpected deadline: ${elapsed} ms`);
      assert.equal(active.requests, 1, 'no automatic retries');
      await page.waitForFunction(() => !document.querySelector('.loading-screen'));
      assert.ok(active.aborted > 0, 'timed out fetch must be aborted');
      if (scenario.retry) {
        active.recovered = true;
        await page.getByRole('button', { name: 'Try again', exact: true }).click();
        await alert.waitFor({ state: 'detached', timeout: 5000 });
        if (scenario.endpoint === '/auth/providers') {
          await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
        } else {
          await page.getByText('Notifications', { exact: true }).last().waitFor();
        }
        assert.equal(active.requests, 1);
      }
      assert.deepEqual(errors, [], 'WASM page must not crash');
      console.log(`PASS ${scenario.endpoint} ${scenario.mode}: ${elapsed} ms; retry=${!!scenario.retry}`);
      await page.close();
    }
  } finally {
    await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {
  console.error(error);
  server.closeAllConnections();
  server.close();
  process.exitCode = 1;
});
