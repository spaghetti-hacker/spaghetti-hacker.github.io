# The Unmapped — prototipo iniziale

Due pagine HTML collegate tra loro, senza framework e senza dipendenze JavaScript.

## Struttura
- `index.html` — La soglia
- `tunnel.html` — Qualcosa alla soglia
- `css/world.css` — stile condiviso, ispirato al CSS fornito (nero, ciano, VT323, terminale)
- `js/world.js` — piccole interazioni dei pannelli

## Anteprima locale
Apri `index.html` nel browser. Per un server locale:
`python3 -m http.server 8000`
e visita `http://localhost:8000/`.

## Pubblicazione
Copia il contenuto della cartella `threshold_world` in una sottocartella del repository GitHub Pages, ad esempio `universe/`.
L'indirizzo sarà `https://TUOUTENTE.github.io/universe/`.

Nota: i font sono caricati da Google Fonts; per un funzionamento completamente offline occorre scaricarli e servirli localmente.


## Risonanza ambientale (prima prova)
Ogni pagina include un comando **ATTIVA RISONANZA** in basso a destra. Genera un drone molto discreto direttamente con Web Audio API: non scarica audio, non richiede file esterni e parte soltanto dopo un clic. È una prima atmosfera sonora, da sostituire o arricchire quando avremo definito meglio il paesaggio acustico del luogo.
