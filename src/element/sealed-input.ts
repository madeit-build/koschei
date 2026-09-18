import { isFromFrameMessage, type Constraints, type FieldUi, type SealedErrorReason, type ToFrame } from '../frame/protocol.ts';
import { discoverRecipient, RecipientError, resolveFormAction } from './recipient.ts';

const UNAVAILABLE_MESSAGE = 'This field is unavailable.';
const INVALID_MESSAGE = 'Please match the requested format.';
const UI_ATTRIBUTES = ['placeholder', 'inputmode', 'autocomplete', 'aria-label'] as const;
const CONSTRAINT_ATTRIBUTES = ['required', 'pattern', 'minlength', 'maxlength'] as const;

export class SealedInputElement extends HTMLElement {
  static formAssociated = true;
  static observedAttributes = ['disabled', ...CONSTRAINT_ATTRIBUTES, ...UI_ATTRIBUTES];

  #internals: ElementInternals;
  #root: ShadowRoot;
  #iframe: HTMLIFrameElement | null = null;
  #recipientOrigin: string | null = null;
  #envelope = '';
  #ready = false;
  #generation = 0;
  #onMessage = (event: MessageEvent) => this.#handleMessage(event);

  constructor() {
    super();
    this.#internals = this.attachInternals();
    this.#root = this.attachShadow({ mode: 'closed', delegatesFocus: true });
    this.#root.innerHTML = `
      <style>
        :host { display: inline-block; width: 20ch; height: 2em; vertical-align: middle; }
        iframe { border: 0; width: 100%; height: 100%; display: block; }
      </style>`;
    this.#markUnavailable();
  }

  get value(): string {
    return this.#envelope;
  }
  set value(_value: string) {
    throw new DOMException('sealed-input value cannot be set by script', 'InvalidStateError');
  }
  get form(): HTMLFormElement | null {
    return this.#internals.form;
  }
  get name(): string {
    return this.getAttribute('name') ?? '';
  }
  get type(): string {
    return 'sealed-input';
  }
  get validity(): ValidityState {
    return this.#internals.validity;
  }
  get validationMessage(): string {
    return this.#internals.validationMessage;
  }
  get willValidate(): boolean {
    return this.#internals.willValidate;
  }
  checkValidity(): boolean {
    return this.#internals.checkValidity();
  }
  reportValidity(): boolean {
    return this.#internals.reportValidity();
  }

  connectedCallback(): void {
    window.addEventListener('message', this.#onMessage);
    void this.#start();
  }

  disconnectedCallback(): void {
    this.#generation++;
    window.removeEventListener('message', this.#onMessage);
    this.#iframe?.remove();
    this.#iframe = null;
    this.#recipientOrigin = null;
    this.#ready = false;
    this.#markUnavailable();
    this.#internals.states.delete('ready');
    this.#internals.states.delete('error');
  }

  attributeChangedCallback(name: string): void {
    if (!this.#ready) return;
    if (name === 'disabled') this.#post({ type: 'sealed-input:disabled', disabled: this.hasAttribute('disabled') });
    else if ((CONSTRAINT_ATTRIBUTES as readonly string[]).includes(name)) this.#post({ type: 'sealed-input:constraints', constraints: this.#constraints() });
  }

  formResetCallback(): void {
    this.#post({ type: 'sealed-input:reset' });
  }

  formDisabledCallback(disabled: boolean): void {
    this.#post({ type: 'sealed-input:disabled', disabled });
  }

  #constraints(): Constraints {
    const number = (attribute: string) => {
      const raw = this.getAttribute(attribute);
      return raw === null ? undefined : Number.parseInt(raw, 10);
    };
    return {
      required: this.hasAttribute('required'),
      pattern: this.getAttribute('pattern') ?? undefined,
      minlength: number('minlength'),
      maxlength: number('maxlength'),
    };
  }

  #ui(): FieldUi {
    return {
      placeholder: this.getAttribute('placeholder') ?? undefined,
      inputmode: this.getAttribute('inputmode') ?? undefined,
      autocomplete: this.getAttribute('autocomplete') ?? undefined,
      label: this.getAttribute('aria-label') ?? this.#labelText() ?? undefined,
    };
  }

  #labelText(): string | null {
    const labels = this.#internals.labels;
    return labels.length > 0 ? (labels[0] as HTMLLabelElement).textContent?.trim() ?? null : null;
  }

  #markUnavailable(): void {
    this.#envelope = '';
    this.#internals.setFormValue(null);
    this.#internals.setValidity({ customError: true }, UNAVAILABLE_MESSAGE);
  }

  #fail(reason: SealedErrorReason): void {
    this.#ready = false;
    this.#markUnavailable();
    this.#internals.states.delete('ready');
    this.#internals.states.add('error');
    this.dispatchEvent(new CustomEvent('sealed-error', { bubbles: true, composed: true, detail: { reason } }));
  }

  async #start(): Promise<void> {
    const generation = ++this.#generation;
    if (!window.isSecureContext) return this.#fail('insecure-context');
    try {
      const { action } = resolveFormAction(this.#internals.form, document.baseURI);
      const info = await discoverRecipient(action.href);
      if (generation !== this.#generation) return;
      this.#recipientOrigin = info.recipientOrigin;
      const iframe = document.createElement('iframe');
      iframe.src = info.frameUrl;
      iframe.referrerPolicy = 'origin';
      iframe.title = this.#ui().label ?? 'Sealed input';
      iframe.addEventListener('load', () => {
        if (generation !== this.#generation) return;
        this.#post({ type: 'sealed-input:init', action: action.href, name: this.name, constraints: this.#constraints(), ui: this.#ui() });
      });
      iframe.addEventListener('error', () => {
        if (generation !== this.#generation) return;
        this.#fail('frame-blocked');
      });
      this.#iframe = iframe;
      this.#root.append(iframe);
    } catch (error) {
      if (generation !== this.#generation) return;
      this.#fail(error instanceof RecipientError ? error.reason : 'recipient-invalid');
    }
  }

  #post(message: ToFrame): void {
    if (!this.#iframe?.contentWindow || !this.#recipientOrigin) return;
    this.#iframe.contentWindow.postMessage(message, this.#recipientOrigin);
  }

  #handleMessage(event: MessageEvent): void {
    if (!this.#iframe || event.source !== this.#iframe.contentWindow || event.origin !== this.#recipientOrigin) return;
    if (!isFromFrameMessage(event.data)) return;
    const message = event.data;
    switch (message.type) {
      case 'sealed-input:ready':
        this.#ready = true;
        this.#internals.states.delete('error');
        this.#internals.states.add('ready');
        this.#envelope = '';
        this.#internals.setFormValue('');
        this.#internals.setValidity(this.hasAttribute('required') ? { customError: true } : {}, INVALID_MESSAGE);
        if (this.matches(':disabled')) this.#post({ type: 'sealed-input:disabled', disabled: true });
        this.dispatchEvent(new CustomEvent('sealed-ready', { bubbles: true, composed: true, detail: { kid: message.kid } }));
        break;
      case 'sealed-input:error':
        this.#fail(message.reason);
        break;
      case 'sealed-input:value':
        this.#envelope = message.envelope;
        this.#internals.setFormValue(message.envelope);
        this.#internals.setValidity(message.valid ? {} : { customError: true }, INVALID_MESSAGE);
        this.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, data: null, inputType: '' }));
        break;
      case 'sealed-input:focus-change':
        if (!message.focused) this.dispatchEvent(new Event('change', { bubbles: true }));
        break;
    }
  }
}

if (!customElements.get('sealed-input')) {
  customElements.define('sealed-input', SealedInputElement);
}
