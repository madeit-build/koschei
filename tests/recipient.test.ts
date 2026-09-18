import { describe, expect, it } from 'vitest';
import { discoverRecipient, isPotentiallyTrustworthy, RecipientError, resolveFormAction } from '../src/element/recipient.ts';

const doc = {
  frame: '/sealed-input/frame.html',
  keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b', kid: 'k1', use: 'enc' }],
};

function fakeFetch(handler: (url: string, init?: RequestInit) => Response): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => handler(String(input), init)) as typeof fetch;
}

describe('isPotentiallyTrustworthy', () => {
  it('accepts https and loopback http only', () => {
    expect(isPotentiallyTrustworthy(new URL('https://api.example.com/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://localhost:4781/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://app.localhost/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://127.0.0.1/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://[::1]/x'))).toBe(true);
    expect(isPotentiallyTrustworthy(new URL('http://api.example.com/x'))).toBe(false);
    expect(isPotentiallyTrustworthy(new URL('ftp://localhost/x'))).toBe(false);
  });
});

describe('discoverRecipient', () => {
  it('fetches the well-known from the action origin with credentials omitted and resolves the frame', async () => {
    let seen: { url: string; init?: RequestInit } | null = null;
    const info = await discoverRecipient(
      'https://api.example.com/enroll?x=1',
      fakeFetch((url, init) => {
        seen = { url, init };
        return new Response(JSON.stringify(doc), { headers: { 'content-type': 'application/json' } });
      }),
    );
    expect(seen).toMatchObject({ url: 'https://api.example.com/.well-known/sealed-input', init: { mode: 'cors', credentials: 'omit' } });
    expect(info).toEqual({ recipientOrigin: 'https://api.example.com', frameUrl: 'https://api.example.com/sealed-input/frame.html', kid: 'k1' });
  });

  it('rejects insecure actions before fetching', async () => {
    await expect(discoverRecipient('http://api.example.com/enroll', fakeFetch(() => new Response('')))).rejects.toMatchObject({ reason: 'insecure-action' });
  });

  it('maps network and shape failures to reasons', async () => {
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response('', { status: 404 })))).rejects.toMatchObject({ reason: 'recipient-unreachable' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => { throw new TypeError('network'); }))).rejects.toMatchObject({ reason: 'recipient-unreachable' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response('<html>', { headers: { 'content-type': 'text/html' } })))).rejects.toMatchObject({ reason: 'recipient-invalid' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response(JSON.stringify({ frame: 'https://other.example/f', keys: doc.keys }), { headers: { 'content-type': 'application/json' } })))).rejects.toMatchObject({ reason: 'recipient-invalid' });
    await expect(discoverRecipient('https://a.example/x', fakeFetch(() => new Response(JSON.stringify({ frame: '/f', keys: [] }), { headers: { 'content-type': 'application/json' } })))).rejects.toBeInstanceOf(RecipientError);
  });
});

function fakeForm(value: string | null): { getAttribute(name: string): string | null } {
  return { getAttribute: () => value };
}

function catchError(run: () => unknown): unknown {
  try {
    run();
    return undefined;
  } catch (error) {
    return error;
  }
}

describe('resolveFormAction', () => {
  it('rejects a null form', () => {
    const error = catchError(() => resolveFormAction(null, 'https://www.example.com/page'));
    expect(error).toBeInstanceOf(RecipientError);
    expect(error).toMatchObject({ reason: 'no-form-action' });
  });

  it('rejects a missing action attribute', () => {
    const error = catchError(() => resolveFormAction(fakeForm(null), 'https://www.example.com/page'));
    expect(error).toMatchObject({ reason: 'no-form-action' });
  });

  it('rejects a blank action attribute', () => {
    const error = catchError(() => resolveFormAction(fakeForm('   '), 'https://www.example.com/page'));
    expect(error).toMatchObject({ reason: 'no-form-action' });
  });

  it('rejects an unparsable action URL', () => {
    const error = catchError(() => resolveFormAction(fakeForm('http://['), 'https://www.example.com/page'));
    expect(error).toMatchObject({ reason: 'no-form-action' });
  });

  it('resolves a relative action against the base URI', () => {
    const { action } = resolveFormAction(fakeForm('/enroll'), 'https://www.example.com/page');
    expect(action.href).toBe('https://www.example.com/enroll');
  });

  it('leaves an absolute action unchanged', () => {
    const { action } = resolveFormAction(fakeForm('https://api.example.com/enroll'), 'https://www.example.com/page');
    expect(action.href).toBe('https://api.example.com/enroll');
  });
});
