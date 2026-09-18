import { expect, test, type Frame, type Page } from '@playwright/test';

const RECIPIENT = 'http://localhost:4781';
const SSN = '123-45-6789';

async function sealedFrame(page: Page): Promise<Frame> {
  await expect.poll(() => page.frames().some((f) => f.url().startsWith(`${RECIPIENT}/sealed-input/frame.html`))).toBe(true);
  return page.frames().find((f) => f.url().startsWith(`${RECIPIENT}/sealed-input/frame.html`)) as Frame;
}

async function waitReady(page: Page): Promise<void> {
  await expect.poll(() => page.locator('sealed-input').evaluate((el) => el.matches(':state(ready)'))).toBe(true);
}

async function envelopeOf(page: Page): Promise<string> {
  return page.locator('sealed-input').evaluate((el: HTMLElement & { value: string }) => el.value);
}

async function typeSsn(page: Page): Promise<void> {
  const frame = await sealedFrame(page);
  await frame.locator('input').pressSequentially(SSN);
  await expect.poll(() => page.locator('sealed-input').evaluate((el: HTMLElement & { value: string }) => el.value.startsWith('sealed1.'))).toBe(true);
  // The frame posts a fresh envelope on every keystroke, valid or not, so the value can
  // already start with "sealed1." after only the first character. Wait for validity to
  // catch up too, so callers see the fully-typed SSN, not a partial one mid-flight.
  await expect.poll(() => page.locator('sealed-input').evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(true);
}

test('the page only ever sees an envelope', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  const seen = await page.evaluate(() => {
    const form = document.getElementById('enroll') as HTMLFormElement;
    const field = form.querySelector('sealed-input') as HTMLElement & { value: string };
    return { value: field.value, formData: new FormData(form).get('ssn'), valid: form.checkValidity(), html: document.documentElement.outerHTML };
  });
  expect(seen.value).toMatch(/^sealed1\.demo\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  expect(seen.formData).toBe(seen.value);
  expect(seen.valid).toBe(true);
  expect(seen.value).not.toContain('6789');
  expect(seen.html).not.toContain(SSN);
});

test('setting .value throws InvalidStateError', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  const error = await page.locator('sealed-input').evaluate((el: HTMLElement & { value: string }) => {
    try {
      el.value = 'x';
      return null;
    } catch (e) {
      return (e as DOMException).name;
    }
  });
  expect(error).toBe('InvalidStateError');
});

test('constraints freeze on first input so validity is not a page-driven oracle', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  const field = page.locator('sealed-input');
  const before = await envelopeOf(page);
  expect(await field.evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(true);
  await field.evaluate((el) => el.setAttribute('pattern', '^9.*'));
  const frame = await sealedFrame(page);
  // The frame replies to every keystroke over the same postMessage channel. Sending keystrokes
  // after setAttribute and waiting for their replies proves, by FIFO ordering, that the frame
  // already processed (and ignored) the constraints message before either of these round-trips.
  await frame.locator('input').press('Backspace');
  await expect.poll(() => envelopeOf(page)).not.toBe(before);
  const mid = await envelopeOf(page);
  await frame.locator('input').pressSequentially('9');
  await expect.poll(() => envelopeOf(page)).not.toBe(mid);
  expect(await field.evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(true);
  expect(await field.evaluate((el: HTMLElement & { validity: ValidityState }) => el.validity.patternMismatch)).toBe(false);
});

test('the recipient opens the envelope for the right slot and rejects the wrong one', async ({ page, request }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  await page.getByRole('button', { name: 'Enroll' }).click();
  await expect(page.locator('#response')).toContainText('200');
  await expect(page.locator('#response')).toContainText('"last4":"6789"');

  const envelope = await page.locator('sealed-input').evaluate((el: HTMLElement & { value: string }) => el.value);
  const replay = await request.post(`${RECIPIENT}/enroll`, { form: { card: envelope } });
  expect(replay.status()).toBe(400);
  expect(await replay.json()).toEqual({ ok: false, code: 'open-failed' });
});

test('fails closed when the action origin is not trustworthy', async ({ page }) => {
  await page.goto('/insecure');
  await expect.poll(() => page.locator('sealed-input').evaluate((el) => el.matches(':state(error)'))).toBe(true);
  const state = await page.evaluate(() => {
    const form = document.getElementById('enroll') as HTMLFormElement;
    const field = form.querySelector('sealed-input') as HTMLElement & { value: string };
    return { value: field.value, valid: form.checkValidity(), observed: document.getElementById('observed')?.textContent ?? '' };
  });
  expect(state.value).toBe('');
  expect(state.valid).toBe(false);
  expect(state.observed).toContain('insecure-action');
});

test('a second init from the page is ignored: slot and frozen constraints survive', async ({ page, request }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  const field = page.locator('sealed-input');
  const before = await envelopeOf(page);

  // A compromised page replays init with a different field name and a looser pattern.
  const handle = await (await sealedFrame(page)).frameElement();
  await handle.evaluate((el: HTMLIFrameElement, recipient: string) => {
    el.contentWindow!.postMessage(
      { type: 'sealed-input:init', action: recipient + '/other', name: 'card', constraints: { required: false, pattern: '^9.*' }, ui: {} },
      '*',
    );
  }, RECIPIENT);

  // Same FIFO argument as the constraints test: the reply to this keystroke proves the frame
  // already handled (and dropped) the forged init.
  const frame = await sealedFrame(page);
  await frame.locator('input').pressSequentially('1');
  await expect.poll(() => envelopeOf(page)).not.toBe(before);
  // "123-45-67891" fails both patterns; backspacing to "123-45-6789" passes only the original
  // SSN pattern, never the forged "^9.*", so validity here shows which constraints govern.
  expect(await field.evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(false);
  const mid = await envelopeOf(page);
  await frame.locator('input').press('Backspace');
  await expect.poll(() => envelopeOf(page)).not.toBe(mid);
  expect(await field.evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(true);

  // The envelope still opens under the original slot (field "ssn"), not the forged "card".
  const envelope = await envelopeOf(page);
  const enroll = await request.post(`${RECIPIENT}/enroll`, { form: { ssn: envelope } });
  expect(enroll.status()).toBe(200);
  expect(await enroll.json()).toEqual({ ok: true, last4: '6789' });
});

test('fails closed with frame-blocked when the frame never reports ready', async ({ page }) => {
  await page.goto('/blocked');
  await expect.poll(() => page.locator('sealed-input').evaluate((el) => el.matches(':state(error)')), { timeout: 10_000 }).toBe(true);
  const state = await page.evaluate(() => {
    const form = document.getElementById('enroll') as HTMLFormElement;
    const field = form.querySelector('sealed-input') as HTMLElement & { value: string };
    return { value: field.value, valid: form.checkValidity(), observed: document.getElementById('observed')?.textContent ?? '' };
  });
  expect(state.observed).toContain('frame-blocked');
  expect(state.value).toBe('');
  expect(state.valid).toBe(false);
});

test('form.reset() clears the sealed value and the required field goes back to invalid', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  await typeSsn(page);
  await page.evaluate(() => (document.getElementById('enroll') as HTMLFormElement).reset());
  await expect.poll(() => envelopeOf(page)).toBe('');
  expect(await page.locator('sealed-input').evaluate((el: HTMLElement & { checkValidity(): boolean }) => el.checkValidity())).toBe(false);
});

test('the disabled attribute reaches the frame input and clears again', async ({ page }) => {
  await page.goto('/');
  await waitReady(page);
  const field = page.locator('sealed-input');
  const frameInput = (await sealedFrame(page)).locator('input');
  await expect.poll(() => frameInput.isDisabled()).toBe(false);
  await field.evaluate((el) => el.setAttribute('disabled', ''));
  await expect.poll(() => frameInput.isDisabled()).toBe(true);
  await field.evaluate((el) => el.removeAttribute('disabled'));
  await expect.poll(() => frameInput.isDisabled()).toBe(false);
});
