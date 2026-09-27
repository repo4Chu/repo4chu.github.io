/* zoom.js — chu@antisec click-to-zoom. vanilla, no deps, ~60 lines.
   click a figure -> fullscreen overlay with the ORIGINAL image (anchor href
   when the figure links out, img src otherwise). click anywhere or esc closes. */
(function () {
  'use strict';

  var lb = document.createElement('div');
  lb.className = 'lb';
  lb.hidden = true;
  lb.setAttribute('role', 'dialog');
  lb.setAttribute('aria-label', 'imagem ampliada');
  var img = document.createElement('img');
  lb.appendChild(img);
  document.body.appendChild(lb);

  function open(fig) {
    var im = fig.querySelector('img');
    if (!im) return;                       // .fig also holds ascii art — nothing to zoom
    var wrap = im.closest('a[href]');
    img.src = wrap ? wrap.getAttribute('href') : im.getAttribute('src');
    img.alt = im.alt || '';
    lb.hidden = false;
    document.documentElement.style.overflow = 'hidden';
  }

  function close() {
    lb.hidden = true;
    img.src = '';
    document.documentElement.style.overflow = '';
  }

  document.addEventListener('click', function (e) {
    if (!lb.hidden) { close(); return; }   // any click closes the overlay
    var fig = e.target.closest('.fig');
    if (fig && e.target.closest('.fig')) {
      e.preventDefault();                  // keep the browser from navigating to the raw file
      open(fig);
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !lb.hidden) close();
  });
})();
