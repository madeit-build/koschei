export type SealedErrorReason =
  | 'recipient-unreachable'
  | 'recipient-invalid'
  | 'frame-blocked'
  | 'no-form-action'
  | 'insecure-action'
  | 'insecure-context';

export const SEALED_ERROR_REASONS: readonly SealedErrorReason[] = [
  'recipient-unreachable',
  'recipient-invalid',
  'frame-blocked',
  'no-form-action',
  'insecure-action',
  'insecure-context',
];

export interface Constraints {
  required: boolean;
  pattern?: string;
  minlength?: number;
  maxlength?: number;
}

export interface FieldUi {
  placeholder?: string;
  inputmode?: string;
  autocomplete?: string;
  label?: string;
}

export type ToFrame =
  | { type: 'sealed-input:init'; action: string; name: string; constraints: Constraints; ui: FieldUi }
  | { type: 'sealed-input:constraints'; constraints: Constraints }
  | { type: 'sealed-input:reset' }
  | { type: 'sealed-input:disabled'; disabled: boolean }
  | { type: 'sealed-input:focus' };

export type FromFrame =
  | { type: 'sealed-input:ready'; kid: string }
  | { type: 'sealed-input:error'; reason: SealedErrorReason }
  | { type: 'sealed-input:value'; envelope: string; empty: boolean; valid: boolean }
  | { type: 'sealed-input:focus-change'; focused: boolean };

export function compilePattern(pattern: string): RegExp | null {
  // HTML anchors the pattern and compiles it with the 'v' flag; a pattern that
  // fails to compile is ignored, matching browser behavior.
  try {
    return new RegExp(`^(?:${pattern})$`, 'v');
  } catch {
    return null;
  }
}

export function validateValue(value: string, constraints: Constraints): boolean {
  if (value.length === 0) return !constraints.required;
  if (constraints.minlength !== undefined && value.length < constraints.minlength) return false;
  if (constraints.maxlength !== undefined && value.length > constraints.maxlength) return false;
  if (constraints.pattern !== undefined) {
    const regex = compilePattern(constraints.pattern);
    if (regex && !regex.test(value)) return false;
  }
  return true;
}

export class FieldState {
  frozen = false;
  value = '';
  constructor(public constraints: Constraints) {}

  // Returns false when the change was ignored because the field is frozen.
  applyConstraints(constraints: Constraints): boolean {
    if (this.frozen) return false;
    this.constraints = constraints;
    return true;
  }

  input(value: string): void {
    this.frozen = true;
    this.value = value;
  }

  reset(): void {
    this.frozen = false;
    this.value = '';
  }

  isValid(): boolean {
    return validateValue(this.value, this.constraints);
  }
}

function isObject(data: unknown): data is Record<string, unknown> {
  return typeof data === 'object' && data !== null;
}

function isConstraints(data: unknown): data is Constraints {
  return (
    isObject(data) &&
    typeof data.required === 'boolean' &&
    (data.pattern === undefined || typeof data.pattern === 'string') &&
    (data.minlength === undefined || typeof data.minlength === 'number') &&
    (data.maxlength === undefined || typeof data.maxlength === 'number')
  );
}

export function isToFrameMessage(data: unknown): data is ToFrame {
  if (!isObject(data) || typeof data.type !== 'string') return false;
  switch (data.type) {
    case 'sealed-input:init':
      return typeof data.action === 'string' && typeof data.name === 'string' && isConstraints(data.constraints) && isObject(data.ui);
    case 'sealed-input:constraints':
      return isConstraints(data.constraints);
    case 'sealed-input:reset':
    case 'sealed-input:focus':
      return true;
    case 'sealed-input:disabled':
      return typeof data.disabled === 'boolean';
    default:
      return false;
  }
}

export function isFromFrameMessage(data: unknown): data is FromFrame {
  if (!isObject(data) || typeof data.type !== 'string') return false;
  switch (data.type) {
    case 'sealed-input:ready':
      return typeof data.kid === 'string';
    case 'sealed-input:error':
      return typeof data.reason === 'string' && (SEALED_ERROR_REASONS as readonly string[]).includes(data.reason);
    case 'sealed-input:value':
      return typeof data.envelope === 'string' && typeof data.empty === 'boolean' && typeof data.valid === 'boolean';
    case 'sealed-input:focus-change':
      return typeof data.focused === 'boolean';
    default:
      return false;
  }
}
