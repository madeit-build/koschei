const form = document.getElementById('enroll');
const field = form.querySelector('sealed-input');
const observed = document.getElementById('observed');
const responseBox = document.getElementById('response');

function render(extra = '') {
  observed.textContent = [
    `constructor = ${field.constructor.name}`,
    `sealed-input.value = ${JSON.stringify(field.value)}`,
    `FormData.get('ssn') = ${JSON.stringify(new FormData(form).get('ssn'))}`,
    `checkValidity() = ${field.checkValidity()}`,
    extra,
  ].join('\n');
}

field.addEventListener('sealed-ready', () => render('state: ready'));
field.addEventListener('sealed-error', (event) => render(`state: error (${event.detail.reason})`));
field.addEventListener('input', () => render('state: ready'));

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.checkValidity()) return form.reportValidity();
  const body = new URLSearchParams(new FormData(form));
  const response = await fetch(form.action, { method: 'POST', body });
  responseBox.textContent = `${response.status} ${await response.text()}`;
});
