import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { generateRecipientKey, wellKnownDocument } from '../src/server/keys.ts';
import { unseal, UnsealError } from '../src/server/unseal.ts';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', 'dist');

export interface DemoServers {
  close(): Promise<void>;
  pageOrigin: string;
  recipientOrigin: string;
}

function log(event: object): void {
  process.stderr.write(JSON.stringify({ time: new Date().toISOString(), ...event }) + '\n');
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk: Buffer) => (body += chunk.toString('utf8')));
    request.on('end', () => resolve(body));
    request.on('error', reject);
  });
}

function send(response: ServerResponse, status: number, body: string | Buffer, headers: Record<string, string>): void {
  response.writeHead(status, headers);
  response.end(body);
}

// Demo-only test switch: delay the well-known for the *frame's* same-origin fetch so the
// element's cross-origin discovery stays fast, its ready timer arms, and the frame's ready
// arrives late. Lets the e2e suite prove a late ready cannot revive a failed field.
let slowFrameWellKnownMs = 0;

export async function startServers(options: { pagePort: number; recipientPort: number }): Promise<DemoServers> {
  const pageOrigin = `http://localhost:${options.pagePort}`;
  const recipientOrigin = `http://localhost:${options.recipientPort}`;
  const key = await generateRecipientKey('demo');
  const wellKnown = JSON.stringify(wellKnownDocument([key.publicJwk]));
  const expect = { origin: pageOrigin, action: `${recipientOrigin}/enroll`, name: 'ssn' };

  const recipient = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', recipientOrigin);
    try {
      const cors = { 'Access-Control-Allow-Origin': pageOrigin, Vary: 'Origin' };
      if (request.method === 'OPTIONS') return send(response, 204, '', { ...cors, 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'content-type' });
      if (url.pathname === '/__demo/slow-frame-well-known' && request.method === 'POST') {
      slowFrameWellKnownMs = Number(url.searchParams.get('ms') ?? '0') || 0;
      return send(response, 204, '', cors);
    }
    if (url.pathname === '/.well-known/sealed-input') {
      if (slowFrameWellKnownMs > 0 && request.headers['sec-fetch-site'] === 'same-origin') {
        await new Promise((resolve) => setTimeout(resolve, slowFrameWellKnownMs));
      }
      return send(response, 200, wellKnown, { ...cors, 'Content-Type': 'application/json' });
    }
      if (url.pathname === '/sealed-input/frame.html') {
        return send(response, 200, await readFile(join(dist, 'frame.html')), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': `frame-ancestors ${pageOrigin}` });
      }
      if (url.pathname === '/sealed-input/frame.js') return send(response, 200, await readFile(join(dist, 'frame.js')), { 'Content-Type': 'text/javascript' });
      if (url.pathname === '/enroll' && request.method === 'POST') {
        const form = new URLSearchParams(await readBody(request));
        const fieldName = form.has('ssn') ? 'ssn' : [...form.keys()][0] ?? 'ssn';
        try {
          const ssn = await unseal(form.get(fieldName) ?? '', { privateKey: key.privateJwk, expect: { ...expect, name: fieldName }, onEvent: log });
          return send(response, 200, JSON.stringify({ ok: true, last4: ssn.slice(-4) }), { ...cors, 'Content-Type': 'application/json' });
        } catch (error) {
          if (error instanceof UnsealError) return send(response, 400, JSON.stringify({ ok: false, code: error.code }), { ...cors, 'Content-Type': 'application/json' });
          log({ event: 'demo.enroll.error', message: error instanceof Error ? error.message : String(error) });
          return send(response, 500, JSON.stringify({ ok: false }), { ...cors, 'Content-Type': 'application/json' });
        }
      }
      send(response, 404, 'not found', { 'Content-Type': 'text/plain' });
    } catch (error) {
      log({ event: 'demo.request.error', route: url.pathname, message: error instanceof Error ? error.message : String(error) });
      if (!response.headersSent) send(response, 500, JSON.stringify({ ok: false }), { 'Content-Type': 'application/json' });
    }
  });

  const renderPage = async (recipient: string, extraAttrs: string) =>
    (await readFile(join(here, 'index.html'), 'utf8')).replaceAll('__RECIPIENT__', recipient).replaceAll('__EXTRA_ATTRS__', extraAttrs);
  const pageCsp = (frameSrc: string) =>
    [`default-src 'self'`, `script-src 'self'`, `style-src 'self' 'unsafe-inline'`, `frame-src ${frameSrc}`, `form-action ${recipientOrigin}`, `connect-src ${recipientOrigin}`].join('; ');

  const page = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', pageOrigin);
    try {
      if (url.pathname === '/') {
        return send(response, 200, await renderPage(recipientOrigin, ''), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': pageCsp(recipientOrigin) });
      }
      // Same page, but the CSP refuses every frame: the browser fires `load` on the blocked
      // frame and no `ready` ever arrives, so the element must time out to frame-blocked.
      // Same page with a short ready timeout and a normal CSP; paired with the slow-frame
      // switch above so the frame's ready arrives after the element has already failed.
      if (url.pathname === '/slow') {
        return send(response, 200, await renderPage(recipientOrigin, ' ready-timeout="400"'), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': pageCsp(recipientOrigin) });
      }
      if (url.pathname === '/blocked') {
        return send(response, 200, await renderPage(recipientOrigin, ' ready-timeout="1500"'), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': pageCsp(`'none'`) });
      }
      if (url.pathname === '/sealed-input.js') return send(response, 200, await readFile(join(dist, 'sealed-input.js')), { 'Content-Type': 'text/javascript' });
      if (url.pathname === '/app.js') return send(response, 200, await readFile(join(here, 'app.js')), { 'Content-Type': 'text/javascript' });
      if (url.pathname === '/insecure') {
        return send(response, 200, await renderPage('http://api.example.invalid', ''), { 'Content-Type': 'text/html; charset=utf-8' });
      }
      send(response, 404, 'not found', { 'Content-Type': 'text/plain' });
    } catch (error) {
      log({ event: 'demo.request.error', route: url.pathname, message: error instanceof Error ? error.message : String(error) });
      if (!response.headersSent) send(response, 500, JSON.stringify({ ok: false }), { 'Content-Type': 'application/json' });
    }
  });

  await new Promise<void>((resolve) => recipient.listen(options.recipientPort, resolve));
  await new Promise<void>((resolve) => page.listen(options.pagePort, resolve));
  log({ event: 'demo.listening', pageOrigin, recipientOrigin });

  return {
    pageOrigin,
    recipientOrigin,
    close: async () => {
      await new Promise<void>((resolve) => recipient.close(() => resolve()));
      await new Promise<void>((resolve) => page.close(() => resolve()));
    },
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await startServers({ pagePort: 4780, recipientPort: 4781 });
}
