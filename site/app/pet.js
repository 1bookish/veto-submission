// Kiki, the companion pet. The team's own drawing, cut into 8 transparent sprites by
// tools/extract-pet.js (web/pet/<mood>.png; the same files ship in the Android app).
//
// Kiki is NOT always on screen. It stays hidden and only appears when there is something to do:
// a warning, an explanation of a code, an X-ray in progress, or a check the user just asked for, 
// then it hides again. A STOP stays until the user taps "Got it".
// Moods change picture, colour and motion (polymorphic warnings resist habituation, 
// Vance/Anderson et al., CHI 2017 / MISQ 2018).

export const MOODS = {
  idle: { label: { en: 'On guard', ar: 'في الحراسة' }, ms: 5000 },
  listening: { label: { en: 'Listening', ar: 'يستمع' }, ms: 0 },
  investigating: { label: { en: 'Investigating', ar: 'يتحقّق' }, ms: 0 },
  thinking: { label: { en: 'Thinking', ar: 'يفكّر' }, ms: 0 },
  advising: { label: { en: 'Advice', ar: 'نصيحة' }, ms: 12000 },
  caution: { label: { en: 'Caution', ar: 'انتبه' }, ms: 15000 },
  stop: { label: { en: 'STOP!', ar: 'توقّف!' }, ms: 0 },
  verified: { label: { en: 'Verified', ar: 'موثّق' }, ms: 6000 }
};
export const spriteUrl = mood => `./pet/${MOODS[mood] ? mood : 'idle'}.png`;

export function mountPet(root, getLang, { gotIt = { en: 'Got it', ar: 'فهمت' } } = {}) {
  root.classList.add('pet-dock');
  root.replaceChildren();
  root.hidden = true;
  const bubble = document.createElement('div');
  bubble.className = 'pet-bubble';
  bubble.setAttribute('role', 'status');
  bubble.setAttribute('aria-live', 'polite');
  const text = document.createElement('div');
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'pet-close';
  bubble.append(text, close);
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'pet-btn';
  const img = document.createElement('img');
  img.alt = '';
  img.draggable = false;
  btn.append(img);
  const tag = document.createElement('span');
  tag.className = 'pet-tag';
  root.append(bubble, btn, tag);
  // preload every mood so switching is instant
  for (const m of Object.keys(MOODS)) { const i = new Image(); i.src = spriteUrl(m); }

  let current = null, lastText = '', hideTimer = null;
  const label = () => MOODS[current]?.label[getLang()] || MOODS[current]?.label.en || '';
  function render() {
    if (!current) return;
    img.src = spriteUrl(current);
    img.className = `pet-img pet-${current}`;
    tag.textContent = label();
    close.textContent = gotIt[getLang()] || gotIt.en;
    root.dataset.state = current;
    btn.setAttribute('aria-label', `Kiki: ${MOODS[current].label.en}`);
  }
  function hide() {
    clearTimeout(hideTimer);
    root.classList.remove('in');
    hideTimer = setTimeout(() => { root.hidden = true; current = null; }, 260);
  }
  function show(mood, msg, ms) {
    clearTimeout(hideTimer);
    if (mood !== current) { current = mood; render(); }
    if (msg) { lastText = msg; text.textContent = msg; bubble.classList.add('show'); } // user-visible text via textContent only
    root.hidden = false;
    requestAnimationFrame(() => root.classList.add('in'));
    const life = ms ?? MOODS[mood].ms;
    if (life) hideTimer = setTimeout(hide, life);
  }
  close.addEventListener('click', hide);
  btn.addEventListener('click', () => {
    if (bubble.classList.contains('show')) bubble.classList.remove('show');
    else if (lastText) { text.textContent = lastText; bubble.classList.add('show'); }
  });
  return {
    /** Show Kiki in a mood with a message. ms: auto-hide after ms (0 = stay). 'sleeping'/'hidden' hide it. */
    set(mood, msg, ms) {
      if (mood === 'sleeping' || mood === 'hidden' || !MOODS[mood]) return hide();
      show(mood, msg, ms);
    },
    hide,
    get state() { return current || 'hidden'; },
    refresh: render
  };
}
