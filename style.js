/* =========================
   BACKGROUND GRID EFFECT
   ========================= */

const gridContainer = document.getElementById('gridContainer');

if (gridContainer) {
  for (let i = 0; i < 30; i++) {
    const line = document.createElement('div');
    line.className = 'grid-line';
    line.style.width = '100%';
    line.style.height = '1px';
    line.style.top = (i * 50) + 'px';
    line.style.animationDelay = (i * 0.1) + 's';
    gridContainer.appendChild(line);
  }

  for (let i = 0; i < 40; i++) {
    const line = document.createElement('div');
    line.className = 'grid-line';
    line.style.width = '1px';
    line.style.height = '100%';
    line.style.left = (i * 50) + 'px';
    line.style.animationDelay = (i * 0.1 + 0.5) + 's';
    gridContainer.appendChild(line);
  }

  const shapeCount = 5;
  for (let i = 0; i < shapeCount; i++) {
    const shape = document.createElement('div');
    shape.className = 'shape';
    const size = Math.random() * 200 + 100;
    shape.style.width = size + 'px';
    shape.style.height = size + 'px';
    shape.style.left = Math.random() * 100 + '%';
    shape.style.top = Math.random() * 100 + '%';
    shape.style.animationDelay = (i * 1.6) + 's';
    shape.style.animationDuration = (Math.random() * 4 + 6) + 's';
    gridContainer.appendChild(shape);
  }
}

/* =========================
   PASSWORD VISIBILITY TOGGLE (GENERIC)
   ========================= */

document.addEventListener('click', function (e) {
  // Use closest() so clicks on the inner SVG (Font Awesome) are also caught
  const icon = e.target.closest('.toggle-icon, .auth-toggle-icon');
  if (icon) {
    // Find the input in the same wrapper div
    const wrapper = icon.closest('.auth-input-wrapper, .input-wrapper') || icon.parentElement;
    const input = wrapper ? wrapper.querySelector('input[type="password"], input[type="text"]') : null;

    if (input) {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';

      icon.classList.toggle('fa-eye');
      icon.classList.toggle('fa-eye-slash');
    }
  }
});