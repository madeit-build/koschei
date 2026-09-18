import { describe, expect, it } from 'vitest';
import { FieldState, isFromFrameMessage, isToFrameMessage, validateValue } from '../src/frame/protocol.ts';

describe('validateValue', () => {
  it('honors required, minlength, maxlength, and the HTML pattern semantics', () => {
    expect(validateValue('', { required: true })).toBe(false);
    expect(validateValue('', { required: false, pattern: '\\d+' })).toBe(true);
    expect(validateValue('12', { required: false, minlength: 3 })).toBe(false);
    expect(validateValue('1234', { required: false, maxlength: 3 })).toBe(false);
    expect(validateValue('123-45-6789', { required: true, pattern: '\\d{3}-?\\d{2}-?\\d{4}' })).toBe(true);
    expect(validateValue('123-45-678', { required: true, pattern: '\\d{3}-?\\d{2}-?\\d{4}' })).toBe(false);
    expect(validateValue('x123-45-6789', { required: true, pattern: '\\d{3}-?\\d{2}-?\\d{4}' })).toBe(false);
  });
  it('treats an invalid pattern as no pattern, like browsers do', () => {
    expect(validateValue('abc', { required: false, pattern: '(' })).toBe(true);
  });
});

describe('FieldState freezes constraints on first input', () => {
  it('accepts constraint changes before input and ignores them after', () => {
    const state = new FieldState({ required: true, pattern: '^1.*' });
    expect(state.applyConstraints({ required: true, pattern: '^2.*' })).toBe(true);
    state.input('2x');
    expect(state.isValid()).toBe(true);
    expect(state.applyConstraints({ required: true, pattern: '^9.*' })).toBe(false);
    expect(state.isValid()).toBe(true);
    state.reset();
    expect(state.value).toBe('');
    expect(state.applyConstraints({ required: true, pattern: '^9.*' })).toBe(true);
  });
});

describe('message guards', () => {
  it('accepts well-formed messages and rejects junk', () => {
    expect(isToFrameMessage({ type: 'sealed-input:init', action: 'https://a/b', name: 'n', constraints: { required: true }, ui: {} })).toBe(true);
    expect(isToFrameMessage({ type: 'sealed-input:reset' })).toBe(true);
    expect(isToFrameMessage({ type: 'sealed-input:init' })).toBe(false);
    expect(isToFrameMessage('sealed-input:init')).toBe(false);
    expect(isFromFrameMessage({ type: 'sealed-input:value', envelope: 'sealed1.k.a.b', empty: false, valid: true })).toBe(true);
    expect(isFromFrameMessage({ type: 'sealed-input:error', reason: 'made-up' })).toBe(false);
  });
});
