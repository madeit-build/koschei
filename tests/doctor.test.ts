import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startServers, type DemoServers } from '../demo/serve.ts';
import { formatDoctor, runDoctor } from '../src/server/doctor.ts';

let servers: DemoServers;
const PAGE = 4790;
const RECIPIENT = 4791;

beforeAll(async () => {
  servers = await startServers({ pagePort: PAGE, recipientPort: RECIPIENT });
});
afterAll(async () => {
  await servers.close();
});

describe('doctor', () => {
  it('passes every check against the demo recipient and page', async () => {
    const checks = await runDoctor({ actionUrl: `${servers.recipientOrigin}/enroll`, pageOrigin: servers.pageOrigin });
    expect(checks.map((c) => [c.name, c.ok])).toEqual([
      ['well-known reachable', true],
      ['well-known parses', true],
      ['well-known allows page origin', true],
      ['frame loads with frame-ancestors', true],
      ['WebCrypto available', true],
      ['page CSP form-action', true],
      ['page CSP frame-src', true],
    ]);
    expect(formatDoctor(checks)).toContain('✓ well-known reachable');
  });

  it('reports a mismatched private key with a hint', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'koschei-'));
    const keyPath = join(dir, 'wrong.jwk');
    const wrong = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    await writeFile(keyPath, JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', wrong.privateKey)), kid: 'demo', use: 'enc' }));
    const checks = await runDoctor({ actionUrl: `${servers.recipientOrigin}/enroll`, privateKeyPath: keyPath });
    const keyCheck = checks.find((c) => c.name === 'private key matches published kid');
    expect(keyCheck?.ok).toBe(false);
    expect(keyCheck?.hint).toMatch(/kid/);
  });

  it('reports an unreachable recipient and stops early', async () => {
    const checks = await runDoctor({ actionUrl: 'http://localhost:1/enroll' });
    expect(checks[0]).toMatchObject({ name: 'well-known reachable', ok: false });
    expect(checks).toHaveLength(1);
  });

  it('reports a malformed action URL as a failed check instead of rejecting', async () => {
    const checks = await runDoctor({ actionUrl: 'not a url' });
    expect(checks).toHaveLength(1);
    expect(checks[0]).toMatchObject({ name: 'action URL parses', ok: false });
    expect(checks[0]?.hint).toBeTruthy();
  });

  it('reports both page CSP checks as failed when the page fetch errors', async () => {
    const checks = await runDoctor({ actionUrl: `${servers.recipientOrigin}/enroll`, pageOrigin: 'http://localhost:1' });
    const last = checks.slice(-2);
    expect(last.map((c) => c.name)).toEqual(['page CSP form-action', 'page CSP frame-src']);
    for (const check of last) {
      expect(check.ok).toBe(false);
      expect(check.hint).toBeTruthy();
    }
  });

  it('flags a well-known that does not allow the page origin', async () => {
    const wellKnownUrl = `${servers.recipientOrigin}/.well-known/sealed-input`;
    const checks = await runDoctor({
      actionUrl: `${servers.recipientOrigin}/enroll`,
      pageOrigin: servers.pageOrigin,
      fetchImpl: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const response = await fetch(input, init);
        if (String(input) !== wellKnownUrl) return response;
        return new Response(await response.text(), { status: response.status, headers: { 'content-type': 'application/json' } });
      }) as typeof fetch,
    });
    const check = checks.find((c) => c.name === 'well-known allows page origin');
    expect(check).toMatchObject({ ok: false });
    expect(check?.hint).toContain('Access-Control-Allow-Origin');
    expect(check?.hint).toContain(servers.pageOrigin);
  });

  it('flags a frame whose frame-ancestors omits the page origin', async () => {
    const checks = await runDoctor({ actionUrl: `${servers.recipientOrigin}/enroll`, pageOrigin: 'http://localhost:1' });
    const check = checks.find((c) => c.name === 'frame loads with frame-ancestors');
    expect(check).toMatchObject({ ok: false });
    expect(check?.hint).toContain('http://localhost:1');
  });

  it('flags a page without the CSP directives', async () => {
    const checks = await runDoctor({
      actionUrl: `${servers.recipientOrigin}/enroll`,
      pageOrigin: servers.pageOrigin,
      fetchImpl: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === `${servers.pageOrigin}/`) return new Response('<html>', { headers: { 'content-type': 'text/html' } });
        return fetch(input, init);
      }) as typeof fetch,
    });
    expect(checks.find((c) => c.name === 'page CSP form-action')).toMatchObject({ ok: false });
    expect(checks.find((c) => c.name === 'page CSP form-action')?.hint).toContain('form-action');
  });
});
