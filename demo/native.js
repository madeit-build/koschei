// Drives the native page: when Ladybird exposes `internals`, types a fixed value and submits, so a
// headless run produces an unseal log line on the recipient without a human at the keyboard.
//
// Posts only the sealed field, not the whole form: /enroll picks 'ssn' when present, otherwise
// the first form key, which on the directive page would be 'name' rather than 'card'.
const fieldName = document.currentScript.dataset.field;
const form = document.getElementById('enroll');
const field = form.elements.namedItem(fieldName);
const observed = document.getElementById('observed');
const responseBox = document.getElementById('response');
const TYPED = fieldName === 'card' ? '4111111111111111' : '123-45-6789';

function render(state) {
  observed.textContent = [
    `constructor = ${field.constructor.name}`,
    `${fieldName}.value = ${JSON.stringify(field.value)}`,
    `FormData.get('${fieldName}') = ${JSON.stringify(new FormData(form).get(fieldName))}`,
    `checkValidity() = ${form.checkValidity()}`,
    `state: ${state}`,
  ].join('\n');
}

async function submit() {
  const body = new URLSearchParams({ [fieldName]: field.value });
  const response = await fetch(form.action, { method: 'POST', body });
  responseBox.textContent = `${response.status} ${await response.text()}`;
}

field.addEventListener('sealed-error', (event) => render(`error (${event.detail.reason})`));
field.addEventListener('sealed-ready', async () => {
  render('ready');
  if (!globalThis.internals) return;
  field.focus();
  internals.sendText(field, TYPED);
  render('typed via internals');
  await submit();
});
form.addEventListener('submit', (event) => { event.preventDefault(); void submit(); });
