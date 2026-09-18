import { parseWellKnown, selectEncryptionKey } from '../server/keys.ts';
import type { SealedErrorReason } from '../frame/protocol.ts';

export class RecipientError extends Error {
  constructor(
    public readonly reason: SealedErrorReason,
    message: string,
  ) {
    super(message);
    this.name = 'RecipientError';
  }
}

export interface RecipientInfo {
  recipientOrigin: string;
  frameUrl: string;
  kid: string;
}

// Mirrors the platform's "potentially trustworthy URL": https, or http on loopback.
export function isPotentiallyTrustworthy(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  const host = url.hostname;
  return host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1' || host === '[::1]';
}

export function resolveFormAction(
  form: { getAttribute(name: string): string | null } | null,
  baseUri: string,
): { action: URL } {
  if (!form) throw new RecipientError('no-form-action', '<sealed-input> must be inside a <form>');
  const attribute = form.getAttribute('action');
  if (attribute === null || attribute.trim() === '') {
    throw new RecipientError('no-form-action', 'the owning <form> must declare an action');
  }
  try {
    return { action: new URL(attribute, baseUri) };
  } catch {
    throw new RecipientError('no-form-action', 'the form action is not a valid URL');
  }
}

export async function discoverRecipient(actionUrl: string, fetchImpl: typeof fetch = fetch): Promise<RecipientInfo> {
  const action = new URL(actionUrl);
  if (!isPotentiallyTrustworthy(action)) {
    throw new RecipientError('insecure-action', 'the form action must be https (or loopback http)');
  }
  const recipientOrigin = action.origin;

  let response: Response;
  try {
    response = await fetchImpl(`${recipientOrigin}/.well-known/sealed-input`, { mode: 'cors', credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new RecipientError('recipient-unreachable', 'could not fetch /.well-known/sealed-input');
  }
  if (!response.ok) throw new RecipientError('recipient-unreachable', `well-known returned ${response.status}`);
  if (!(response.headers.get('content-type') ?? '').startsWith('application/json')) {
    throw new RecipientError('recipient-invalid', 'well-known is not application/json');
  }

  let kid: string;
  let frameUrl: URL;
  try {
    const doc = parseWellKnown(await response.json());
    kid = selectEncryptionKey(doc).kid;
    frameUrl = new URL(doc.frame, recipientOrigin);
  } catch {
    throw new RecipientError('recipient-invalid', 'well-known is malformed');
  }
  if (frameUrl.origin !== recipientOrigin) {
    throw new RecipientError('recipient-invalid', 'well-known.frame must be same-origin with the recipient');
  }
  return { recipientOrigin, frameUrl: frameUrl.href, kid };
}
