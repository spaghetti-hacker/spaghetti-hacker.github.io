document.addEventListener("DOMContentLoaded", () => {
  const decodeButton = document.querySelector("#decode-button");
  const decodedPanel = document.querySelector("#decoded-panel");
  const continueLink = document.querySelector("#continue-link");
  const gateStatus = document.querySelector("#gate-status");

  if (decodeButton && decodedPanel) {
    const activate = () => {
      decodedPanel.hidden = false;
      decodeButton.textContent = "[ SEQUENZA INTERPRETATA ]";
      if (continueLink) continueLink.setAttribute("aria-disabled", "false");
      if (gateStatus) gateStatus.textContent = "RISPOSTA RILEVATA // VARCO ACCESSIBILE";
    };
    decodeButton.addEventListener("click", activate);
    document.querySelectorAll('[data-action="decode"]').forEach(button => {
      button.addEventListener("click", activate);
    });
  }

  const artifactButton = document.querySelector("#artifact-button");
  const artifactPanel = document.querySelector("#artifact-panel");
  if (artifactButton && artifactPanel) {
    artifactButton.addEventListener("click", () => {
      const opening = artifactPanel.hidden;
      artifactPanel.hidden = !opening;
      artifactButton.textContent = opening ? "[ NASCONDI I BYTE ]" : "[ OSSERVA I BYTE ]";
    });
  }
});


// Risonanza ambientale sintetizzata nel browser: nessun file audio esterno.
(() => {
  const button = document.querySelector('[data-sound-toggle]');
  if (!button) return;
  const label = button.querySelector('[data-sound-label]');
  let context = null;
  let nodes = [];
  let active = false;

  function startSound() {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) { label.textContent = 'AUDIO NON SUPPORTATO'; button.disabled = true; return; }
    context = context || new AudioContext();
    context.resume();
    const master = context.createGain();
    master.gain.value = 0.0001;
    master.connect(context.destination);

    // Due frequenze basse e leggermente dissonanti: un ronzio distante, non una melodia.
    [43.7, 65.4, 87.3].forEach((frequency, index) => {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = index === 1 ? 'triangle' : 'sine';
      oscillator.frequency.value = frequency;
      gain.gain.value = index === 0 ? 0.42 : 0.16;
      oscillator.connect(gain); gain.connect(master); oscillator.start();
      nodes.push(oscillator, gain);
    });
    const lfo = context.createOscillator();
    const lfoGain = context.createGain();
    lfo.frequency.value = 0.08; lfoGain.gain.value = 0.00016;
    lfo.connect(lfoGain); lfoGain.connect(master.gain); lfo.start();
    nodes.push(lfo, lfoGain, master);
    master.gain.setTargetAtTime(0.035, context.currentTime, 2.5);
  }

  function stopSound() {
    if (!context || !active) return;
    const master = nodes[nodes.length - 1];
    if (master && master.gain) master.gain.setTargetAtTime(0.0001, context.currentTime, 0.8);
    window.setTimeout(() => {
      nodes.forEach(node => { try { if (typeof node.stop === 'function') node.stop(); } catch (_) {} });
      nodes = [];
    }, 2800);
  }

  button.addEventListener('click', () => {
    active = !active;
    if (active) { startSound(); label.textContent = 'DISATTIVA RISONANZA'; }
    else { stopSound(); label.textContent = 'ATTIVA RISONANZA'; }
    button.setAttribute('aria-pressed', String(active));
  });
})();
