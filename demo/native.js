// Drives the native page: when Ladybird exposes `internals`, types a fixed value and submits, so a
// headless run produces an unseal log line on the recipient without a human at the keyboard.
//
// sealed-ready/sealed-error bubble, and the field's async setup can start the moment it's parsed,
// well before DOMContentLoaded. So the listeners below are registered at top level (native.html
// loads this script in <head>, before the form), not inside the DOMContentLoaded handler, and the
// outcome is captured in a promise so a DOMContentLoaded handler that runs later still sees it.
//
// Posts only the sealed field, not the whole form: /enroll picks 'ssn' when present, otherwise
// the first form key, which on the directive page would be 'name' rather than 'card'.
const fieldName = document.currentScript.dataset.field;
const TYPED = fieldName === 'card' ? '4111111111111111' : '123-45-6789';

const readiness = new Promise((resolve) => {
  document.addEventListener('sealed-ready', () => resolve({ ready: true }), { once: true });
  document.addEventListener('sealed-error', (event) => resolve({ ready: false, reason: event.detail.reason }), { once: true });
});

let form, field, observed, responseBox;

function render(state) {
  observed.textContent = [
    `constructor = ${field.constructor.name}`,
    `${fieldName}.value = ${JSON.stringify(field.value)}`,
    `FormData.get('${fieldName}') = ${JSON.stringify(new FormData(form).get(fieldName))}`,
    `checkValidity() = ${field.checkValidity()}`,
    `state: ${state}`,
  ].join('\n');
}

async function submit() {
  const body = new URLSearchParams({ [fieldName]: field.value });
  const response = await fetch(form.action, { method: 'POST', body });
  responseBox.textContent = `${response.status} ${await response.text()}`;
}

document.addEventListener('DOMContentLoaded', async () => {
  form = document.getElementById('enroll');
  field = form.elements.namedItem(fieldName);
  observed = document.getElementById('observed');
  responseBox = document.getElementById('response');
  form.addEventListener('submit', (event) => { event.preventDefault(); void submit(); });

  render('waiting');
  const outcome = await readiness;
  if (!outcome.ready) return render(`error (${outcome.reason})`);
  render('ready');
  if (!globalThis.internals) return;
  field.focus();
  internals.sendText(field, TYPED);
  render('typed via internals');
  await submit();
});
