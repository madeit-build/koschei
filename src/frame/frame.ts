import { canonicalAction, type Slot } from '../envelope.ts';
import { suite } from '../hpke.ts';
import { sealValue } from '../seal.ts';
import { parseWellKnown, selectEncryptionKey } from '../server/keys.ts';
import { FieldState, isToFrameMessage, type FromFrame, type SealedErrorReason, type ToFrame } from './protocol.ts';

const input = document.querySelector('input') as HTMLInputElement;

let parentOrigin: string | null = null;
let slot: Slot | null = null;
let recipient: { kid: string; publicKey: CryptoKey } | null = null;
let state: FieldState | null = null;
let sealSequence = 0;

function post(message: FromFrame): void {
  if (parentOrigin === null) return;
  window.parent.postMessage(message, parentOrigin);
}

function fail(reason: SealedErrorReason): void {
  input.disabled = true;
  input.toggleAttribute('data-unavailable', true);
  post({ type: 'sealed-input:error', reason });
}

async function loadRecipient(): Promise<{ kid: string; publicKey: CryptoKey }> {
  const response = await fetch('/.well-known/sealed-input', { credentials: 'omit', cache: 'no-store' });
  if (!response.ok) throw new Error('recipient-unreachable');
  const doc = parseWellKnown(await response.json());
  const { kid, jwk } = selectEncryptionKey(doc);
  const { kid: _kid, use: _use, ...importable } = jwk as JsonWebKey & { kid?: string; use?: string };
  return { kid, publicKey: await suite.kem.importKey('jwk', importable, true) };
}

async function publishValue(): Promise<void> {
  if (!state || !recipient || !slot) return;
  const sequence = ++sealSequence;
  const value = state.value;
  const valid = state.isValid();
  if (value.length === 0) {
    post({ type: 'sealed-input:value', envelope: '', empty: true, valid });
    return;
  }
  const envelope = await sealValue({ value, kid: recipient.kid, recipientPublicKey: recipient.publicKey, slot });
  // A newer keystroke may have sealed while we awaited; only the latest wins.
  if (sequence !== sealSequence) return;
  post({ type: 'sealed-input:value', envelope, empty: false, valid });
}

async function handleInit(message: Extract<ToFrame, { type: 'sealed-input:init' }>): Promise<void> {
  let action: URL;
  try {
    action = new URL(message.action);
  } catch {
    return fail('recipient-invalid');
  }
  // The frame seals only to its own origin's key. A page cannot redirect the seal.
  if (action.origin !== location.origin) return fail('recipient-invalid');

  try {
    recipient = await loadRecipient();
  } catch (error) {
    return fail(error instanceof Error && error.message === 'recipient-unreachable' ? 'recipient-unreachable' : 'recipient-invalid');
  }

  slot = { origin: parentOrigin as string, action: canonicalAction(action.href), name: message.name };
  state = new FieldState(message.constraints);

  input.placeholder = message.ui.placeholder ?? '';
  if (message.ui.inputmode) input.inputMode = message.ui.inputmode;
  input.autocomplete = (message.ui.autocomplete ?? 'off') as AutoFill;
  input.setAttribute('aria-label', message.ui.label ?? 'Sealed input');
  input.removeAttribute('data-unavailable');
  input.disabled = false;
  post({ type: 'sealed-input:ready', kid: recipient.kid });
}

window.addEventListener('message', (event: MessageEvent) => {
  if (event.source !== window.parent) return;
  if (parentOrigin === null) parentOrigin = event.origin;
  else if (event.origin !== parentOrigin) return;
  if (!isToFrameMessage(event.data)) return;

  switch (event.data.type) {
    case 'sealed-input:init':
      void handleInit(event.data);
      break;
    case 'sealed-input:constraints':
      if (state && state.applyConstraints(event.data.constraints)) void publishValue();
      break;
    case 'sealed-input:reset':
      if (state) {
        state.reset();
        input.value = '';
        void publishValue();
      }
      break;
    case 'sealed-input:disabled':
      if (recipient) input.disabled = event.data.disabled;
      break;
    case 'sealed-input:focus':
      input.focus();
      break;
  }
});

input.addEventListener('input', () => {
  if (!state) return;
  state.input(input.value);
  void publishValue();
});
input.addEventListener('focus', () => post({ type: 'sealed-input:focus-change', focused: true }));
input.addEventListener('blur', () => post({ type: 'sealed-input:focus-change', focused: false }));
