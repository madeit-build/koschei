import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { parseWellKnown, selectEncryptionKey, type WellKnownDocument } from './keys.ts';

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
  hint?: string;
}

export interface DoctorOptions {
  actionUrl: string;
  privateKeyPath?: string;
  pageOrigin?: string;
  fetchImpl?: typeof fetch;
}

function cspDirective(header: string | null, directive: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name === directive) return values.join(' ');
  }
  return null;
}

// Checks run in the order they most often fail; a failure that makes later
// checks meaningless stops the run.
export async function runDoctor(options: DoctorOptions): Promise<DoctorCheck[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const checks: DoctorCheck[] = [];
  let recipientOrigin: string;
  try {
    recipientOrigin = new URL(options.actionUrl).origin;
  } catch {
    checks.push({ name: 'action URL parses', ok: false, detail: `"${options.actionUrl}" is not an absolute URL`, hint: 'Pass the absolute form action, e.g. https://api.example.com/enroll.' });
    return checks;
  }

  let response: Response;
  try {
    response = await fetchImpl(`${recipientOrigin}/.well-known/sealed-input`, { credentials: 'omit', cache: 'no-store' });
  } catch (error) {
    checks.push({ name: 'well-known reachable', ok: false, detail: `${recipientOrigin}/.well-known/sealed-input: ${error instanceof Error ? error.message : String(error)}`, hint: 'Serve /.well-known/sealed-input from the action origin (koschei init writes it).' });
    return checks;
  }
  const contentType = response.headers.get('content-type') ?? '';
  const reachable = response.ok && contentType.startsWith('application/json');
  checks.push({ name: 'well-known reachable', ok: reachable, detail: `${response.status}, ${contentType || 'no content-type'}`, ...(reachable ? {} : { hint: 'Return 200 with Content-Type: application/json.' }) });
  if (!reachable) return checks;

  let doc: WellKnownDocument;
  let kid: string;
  let frameUrl: URL;
  try {
    doc = parseWellKnown(await response.json());
    kid = selectEncryptionKey(doc).kid;
    frameUrl = new URL(doc.frame, recipientOrigin);
    if (frameUrl.origin !== recipientOrigin) throw new TypeError('frame is not same-origin with the recipient');
    checks.push({ name: 'well-known parses', ok: true, detail: `${doc.keys.length} key(s), kid=${kid}, frame=${doc.frame}` });
  } catch (error) {
    checks.push({ name: 'well-known parses', ok: false, detail: error instanceof Error ? error.message : String(error), hint: 'Needs { frame: "<same-origin path>", keys: [ { kty: "EC", crv: "P-256", x, y, kid, use: "enc" } ] }.' });
    return checks;
  }

  try {
    const frameResponse = await fetchImpl(frameUrl.href, { credentials: 'omit', cache: 'no-store' });
    const ancestors = cspDirective(frameResponse.headers.get('content-security-policy'), 'frame-ancestors');
    const ok = frameResponse.ok && ancestors !== null;
    checks.push({ name: 'frame loads with frame-ancestors', ok, detail: `${frameResponse.status}, frame-ancestors ${ancestors ?? 'missing'}`, ...(ok ? {} : { hint: `Send Content-Security-Policy: frame-ancestors <embedding origin> with ${doc.frame}.` }) });
  } catch (error) {
    checks.push({ name: 'frame loads with frame-ancestors', ok: false, detail: error instanceof Error ? error.message : String(error), hint: `Serve ${doc.frame} from the recipient origin.` });
  }

  if (options.privateKeyPath) {
    try {
      const privateJwk = JSON.parse(await readFile(options.privateKeyPath, 'utf8')) as JsonWebKey & { kid?: string };
      const published = doc.keys.find((key) => (key as { kid?: string }).kid === privateJwk.kid);
      const matches = published !== undefined && published.x === privateJwk.x && published.y === privateJwk.y;
      checks.push({ name: 'private key matches published kid', ok: matches, detail: `local kid=${privateJwk.kid ?? 'none'}, published kids=${doc.keys.map((k) => (k as { kid?: string }).kid).join(',')}`, ...(matches ? {} : { hint: 'The private JWK kid, x, and y must match a key in the well-known. Re-run koschei init or publish the matching public key.' }) });
    } catch (error) {
      checks.push({ name: 'private key matches published kid', ok: false, detail: error instanceof Error ? error.message : String(error), hint: 'Pass --private <path to the JWK koschei init wrote>.' });
    }
  }

  const webcrypto = typeof crypto?.subtle?.deriveBits === 'function';
  checks.push({ name: 'WebCrypto available', ok: webcrypto, detail: webcrypto ? 'crypto.subtle present (ECDH, HKDF, AES-GCM)' : 'crypto.subtle missing', ...(webcrypto ? {} : { hint: 'Run on Node 20+.' }) });

  if (options.pageOrigin) {
    try {
      const pageResponse = await fetchImpl(`${options.pageOrigin}/`, { credentials: 'omit', cache: 'no-store' });
      const csp = pageResponse.headers.get('content-security-policy');
      for (const directive of ['form-action', 'frame-src']) {
        const value = cspDirective(csp, directive);
        const ok = value !== null && value.split(/\s+/).includes(recipientOrigin);
        checks.push({ name: `page CSP ${directive}`, ok, detail: value === null ? `${directive} missing` : `${directive} ${value}`, ...(ok ? {} : { hint: `Add \`${directive} ${recipientOrigin}\` to the page's Content-Security-Policy so a script cannot ${directive === 'form-action' ? 'retarget the form' : 'swap in another frame'}.` }) });
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      for (const directive of ['form-action', 'frame-src']) {
        checks.push({ name: `page CSP ${directive}`, ok: false, detail, hint: 'Pass --page <embedding origin> that serves the form.' });
      }
    }
  }

  return checks;
}

export function formatDoctor(checks: DoctorCheck[]): string {
  return checks
    .map((check) => `${check.ok ? '✓' : '!'} ${check.name}  ${check.detail}${check.hint && !check.ok ? `\n    -> ${check.hint}` : ''}`)
    .join('\n');
}

export async function runDoctorCli(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { private: { type: 'string' }, page: { type: 'string' } },
  });
  const actionUrl = positionals[0];
  if (!actionUrl) {
    process.stderr.write('usage: koschei doctor <action-url> [--private path] [--page origin]\n');
    return 2;
  }
  const checks = await runDoctor({ actionUrl, privateKeyPath: values.private, pageOrigin: values.page });
  process.stdout.write(formatDoctor(checks) + '\n');
  return checks.every((check) => check.ok) ? 0 : 1;
}
