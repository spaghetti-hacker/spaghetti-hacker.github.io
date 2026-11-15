#!/usr/bin/env python3
"""
news_fetcher.py - Raccoglie le notizie di cybersecurity dai feed RSS e genera
news_db.json conforme a news_schema.json.

Fonti: The Hacker News, SecurityWeek, BleepingComputer, Red Hot Cyber,
       Cybersecurity360, Securityinfo.it

Dipendenze:
    pip install feedparser requests            (obbligatorie)
    pip install jsonschema                     (opzionale, validazione finale)

Modalità LLM (consigliata):
    export ANTHROPIC_API_KEY=sk-ant-...
    Con la chiave presente, titolo, riassunto (in italiano, parafrasato),
    categoria, severità e tag vengono generati da Claude. Senza chiave si usa
    un fallback a regole/parole chiave: funziona, ma titoli e riassunti
    restano nella lingua originale e sono solo un estratto, non una parafrasi.

Uso:
    python news_fetcher.py                      # ultimi 7 giorni -> news_db.json
    python news_fetcher.py --days 3 --max-items 40
    python news_fetcher.py --no-llm             # forza il fallback
"""

import argparse
import difflib
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
import requests

# --------------------------------------------------------------------------
# Configurazione
# --------------------------------------------------------------------------

# Se un feed cambiasse indirizzo, basta aggiornare l'URL qui.
FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Guerre di Rete", "https://www.guerredirete.it/feed/"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Red Hot Cyber", "https://www.redhotcyber.com/feed/"),
    ("Cybersecurity360", "https://www.cybersecurity360.it/feed/"),
    ("Securityinfo.it", "https://www.securityinfo.it/feed/"),
]

CATEGORIES = ["ransomware", "vuln", "breach", "apt", "malware",
              "supply-chain", "ics", "policy", "business", "general"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

USER_AGENT = "Mozilla/5.0 (compatible; news-fetcher/1.0; +personal-use)"
HTTP_TIMEOUT = 25
LLM_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TAG_RE = re.compile(r"<[^>]+>")
SKIP_TITLE_RE = re.compile(
    r"weekly recap|newsletter|podcast|webinar|\bwhitepaper\b|sponsored|"
    r"giveaway|\bdeal(s)?\b|\bsconti\b|\bcorso\b|"
    # offerte commerciali e rassegne di più notizie: non sono una notizia sola
    r"\boffert[ae]\b|\bsconto\b|black friday|\bcoupon\b|\bpromo\b|"
    r"in other news|threatsday|week in review|weekly (roundup|digest)", re.I)

# --------------------------------------------------------------------------
# Regole di classificazione (fallback senza LLM, EN + IT)
# --------------------------------------------------------------------------
# Per ogni categoria ci sono due liste di espressioni regolari con confini di
# parola (\b): così "apt" non scatta su "adapt" né "rce" su "source".
#   strong = termini specifici, quasi sempre indicativi della categoria
#   weak   = termini generici, che da soli non bastano
# Ogni lista viene cercata separatamente nel titolo, nei tag del feed e nel
# corpo; contano i termini distinti trovati, non quante volte compaiono.


def _rx(*patterns):
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.I)


CATEGORY_RULES = {
    "ransomware": {
        "strong": _rx(r"\bransomware\b", r"\bdouble[- ]extortion\b", r"\bleak site\b",
                      r"\bransom note\b",
                      r"\b(lockbit|blackcat|alphv|akira|qilin|clop|rhysida|black basta|"
                      r"conti|revil|ransomhub|hunters international)\b"),
        # estorsione/riscatto sono troppo generici (minacce bomba, sextortion, ...)
        "weak": _rx(r"\bransom\b", r"\bextortion\b", r"\bestorsion[ei]\b", r"\briscatto\b"),
    },
    "ics": {
        "strong": _rx(r"\bscada\b", r"\bindustrial control( systems?)?\b", r"\bplcs?\b",
                      r"\bics\b", r"\boperational technology\b",
                      r"\bot (security|networks?|environments?|systems?)\b",
                      r"\bsistemi (industriali|di controllo industriale)\b",
                      r"\bhmi\b", r"\bmodbus\b"),
        "weak": _rx(r"\bindustrial\b", r"\bindustriali?\b", r"\bcritical infrastructure\b",
                    r"\binfrastrutture critiche\b"),
    },
    "supply-chain": {
        "strong": _rx(r"\bsupply[- ]chain\b", r"\bnpm\b", r"\bpypi\b", r"\brubygems\b",
                      r"\bgithub actions\b", r"\btyposquat\w*", r"\bdependency confusion\b",
                      r"\bmalicious (packages?|extensions?|libraries|npm|pypi)\b",
                      r"\bcatena di fornitura\b", r"\bpacchetti malevoli\b",
                      r"\bvs ?code extensions?\b", r"\btrojani[sz]ed\b", r"\bci/cd\b",
                      r"\bhidden implants?\b", r"\bmalicious (\w+ ){0,3}extensions?\b"),
        "weak": _rx(r"\bdependenc(y|ies)\b", r"\bopen[- ]source (package|librar)\w*",
                    r"\bgithub (accounts?|repositor\w+)\b", r"\bpipelines?\b"),
    },
    "apt": {
        "strong": _rx(r"\bapt[- ]?\d{1,2}\b", r"\bapt (group|actor|campaign)s?\b",
                      r"\bnation[- ]state\b", r"\bstate[- ](sponsored|backed)\b",
                      r"\bcyber[- ]?espionage\b", r"\bespionage\b", r"\bspionaggio\b",
                      r"\bsponsorizzat\w*",
                      r"\b(lazarus|sandworm|turla|kimsuky|muddywater|volt typhoon|"
                      r"salt typhoon|fancy bear|cozy bear|charming kitten|oilrig|andariel)\b",
                      r"\bthreat actors? (linked|tied|associated|affiliated)\b",
                      r"\b(chinese|russian|iranian|north korean)[- ]"
                      r"(hackers?|threat actors?|state|linked|nexus|backed|campaign|apt|"
                      r"group|attackers?|operatives?|espionage)\b",
                      r"\battori statali\b", r"\bguerra ibrida\b"),
        "weak": _rx(r"\bnorth korea\w*", r"\bgeopolitic\w*", r"\bcyber[- ]?war(fare)?\b",
                    r"\bguerra cibernetica\b",
                    r"\b(iran|iraniani?|iranian|cina|cinesi|china|russia|russi|"
                    r"russian|corea del nord|nordcoreani?)\b"),
    },
    "breach": {
        "strong": _rx(r"\bdata breach(es)?\b", r"\bdata leaks?\b",
                      r"\bleaked (data|database|credentials)\b",
                      r"\bstolen (data|credentials)\b",
                      r"\bexposed (database|data|server|bucket)s?\b", r"\bdata exposure\b",
                      r"\bdata theft\b", r"\bexfiltrat\w+",
                      r"\bviolazione (dei|di) dati\b", r"\bfurto di dati\b",
                      r"\bdati (rubati|esposti|trafugati)\b",
                      r"\bexposed (online|publicly)\b", r"\bleaking\b",
                      r"\bunauthori[sz]ed access\b", r"\baccesso non autorizzato\b",
                      r"\baccesso ai dati\b", r"\bsecurity (breach|incident)\b",
                      r"\bstolen (\w+ ){0,2}(keys?|tokens?|secrets?|credentials?|data)\b",
                      r"\b\d[\d.,]*\s?(million|billion|milioni di|miliardi di) "
                      r"(records?|accounts?|users?|customers?|utenti|clienti)\b",
                      r"\bshinyhunters\b"),
        "weak": _rx(r"\bbreach(es|ed)?\b", r"\bleak(s|ed)?\b", r"\bhacked\b",
                    r"\bcompromised accounts?\b", r"\b(customer|user|client) data\b"),
    },
    "malware": {
        "strong": _rx(r"\bmalware\b", r"\btrojans?\b", r"\bbotnets?\b",
                      r"\b(info)?stealers?\b", r"\bbackdoors?\b", r"\bspyware\b",
                      r"\bwipers?\b", r"\brootkits?\b", r"\bcrypto-?miners?\b",
                      r"\bkeyloggers?\b", r"\brats?\b", r"\bcodice malevolo\b", r"\bworms?\b",
                      r"\breverse shells?\b",
                      # famiglie note: estendi questa lista quando ne compaiono di nuove
                      r"\b(gootloader|castlerat|stealc|lumma|redline|vidar|emotet|qakbot|"
                      r"trickbot|icedid|remcos|asyncrat|agent tesla|formbook|xworm|darkgate|"
                      r"pikabot|bumblebee|smokeloader|cobalt strike|gsocket)\b"),
        "weak": _rx(r"\bloaders?\b", r"\bphishing\b", r"\b(smishing|vishing)\b",
                    r"\bclickfix\b", r"\bmalicious\b", r"\bmalevol\w+", r"\bscams?\b"),
    },
    "vuln": {
        "strong": _rx(r"\bcve-\d{4}-\d{4,7}\b", r"\bzero[- ]days?\b", r"\b0[- ]days?\b",
                      r"\bremote code execution\b", r"\brce\b", r"\bprivilege escalation\b",
                      r"\bcvss\b", r"\bvulnerabilit\w*", r"\bpatch tuesday\b",
                      r"\bsecurity (patch|advisor)\w*", r"\bkev\b",
                      r"\baggiornament[oi] di sicurezza\b", r"\bauthentication bypass\b",
                      r"\bsql injection\b", r"\bbuffer overflow\b", r"\bpath traversal\b",
                      r"\bcross[- ]site scripting\b", r"\bxss\b", r"\bflaws?\b", r"\bfall[ae]\b"),
        # "security updates" è debole: gli aggiornamenti spesso rompono cose (stampa,
        # attivazione) senza che la notizia riguardi una vulnerabilità
        "weak": _rx(r"\bsecurity updates?\b", r"\bpatch(es|ed|ing)?\b", r"\bbugs?\b",
                    r"\bexploit(s|ed|ing|ation)?\b", r"\bsfruttat\w+", r"\bsfruttament\w+"),
    },
    "policy": {
        "strong": _rx(r"\bnis2\b", r"\bgdpr\b", r"\bregulation\b", r"\bregolament\w+",
                      r"\blegislation\b", r"\bsanction(s|ed)?\b", r"\bindict(ed|ment)\b",
                      r"\bextradit\w+", r"\bsentenced\b", r"\bconvicted\b",
                      r"\bpleads? guilty\b", r"\bcondannat\w+", r"\bnormativa\b",
                      r"\bgarante (per la )?(protezione dei dati|privacy)\b",
                      r"\beuropol\b", r"\binterpol\b", r"\bexecutive order\b",
                      r"\bdirettiva\b", r"\bcyber resilience act\b", r"\benisa\b",
                      r"\b(?-i:DORA)\b", r"\bcircia\b", r"\bincident reporting\b"),
        "weak": _rx(r"\barrest(s|ed)?\b", r"\barrestat\w+", r"\blaws?\b", r"\blegge\b",
                    r"\bacn\b", r"\bcourt\b", r"\btribunale\b", r"\bfin(e|es|ed)\b",
                    r"\bgarante\b", r"\bprivacy\b", r"\benforcement\b", r"\bpolice\b",
                    r"\bcrackdown\b", r"\bsuspects?\b",
                    r"\bsanzion\w+", r"\bcompliance\b", r"\bgovernment\b", r"\bgoverno\b",
                    r"\bsenate\b", r"\bparliament\b", r"\bparlamento\b"),
    },
    "business": {
        "strong": _rx(r"\bacquires?\b", r"\bacquired\b", r"\bto acquire\b",
                      r"\bacquisition\b", r"\bacquisizion\w+", r"\bfunding\b",
                      r"\braises? [$€£]\s?\d", r"\bseries [a-d]\b", r"\bipo\b",
                      r"\blayoffs?\b", r"\bfinanziament\w+", r"\bmerger\b"),
        "weak": _rx(r"\bpartnership\b", r"\bappoints?\b", r"\blaunch(es|ed)?\b",
                    r"\bceo\b", r"\bstartup\b", r"\bmarket\b", r"\bmercato\b"),
    },
}

# A parità di punteggio vince la categoria più specifica (prima in lista).
PRIORITY = ["ransomware", "ics", "supply-chain", "apt", "breach", "malware",
            "vuln", "policy", "business"]
# Se il titolo parla di un attacco specifico, questo batte la falla/malware/breach
# che l'attacco usa o provoca ("Ransomware sfrutta uno zero-day" -> ransomware).
SPECIFIC_CATS = ("ransomware", "supply-chain", "apt", "ics")
OVERRIDABLE = ("vuln", "malware", "breach")
MIN_SCORE = 4  # sotto questa soglia la categoria resta "general"

# Tag di feed troppo generici per finire nel campo "tags"
GENERIC_TAGS = {
    "news", "security", "cybersecurity", "cyber security", "cyber", "sicurezza",
    "sicurezza informatica", "uncategorized", "attualità", "attualita", "featured",
    "in evidenza", "hacking news", "hacking", "tecnologia", "technology", "blog",
    "articoli", "notizie", "approfondimenti", "editorial",
}

# --------------------------------------------------------------------------
# Utilità
# --------------------------------------------------------------------------


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def clean_text(raw):
    if not raw:
        return ""
    txt = TAG_RE.sub(" ", raw)
    txt = html.unescape(txt)
    return re.sub(r"\s+", " ", txt).strip()


def clean_url(url):
    """Forza https, toglie tracking e fragment. Restituisce None se non è un
    URL diretto di un articolo (richiesto dallo schema)."""
    if not url:
        return None
    p = urlsplit(url.strip())
    if p.scheme == "http":
        p = p._replace(scheme="https")
    if p.scheme != "https" or not p.netloc:
        return None
    if p.path in ("", "/"):
        return None
    q = [(k, v) for k, v in parse_qsl(p.query)
         if not k.lower().startswith("utm_") and k.lower() not in ("fbclid", "gclid", "ref")]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def entry_datetime(entry):
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        t = entry.get(key)
        if t:
            return datetime(*t[:6], tzinfo=timezone.utc)
    return None


def norm_title(t):
    return re.sub(r"[^a-z0-9 ]", "", t.lower())


# --------------------------------------------------------------------------
# Download feed
# --------------------------------------------------------------------------


def fetch_articles(days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    articles = []
    for name, url in FEEDS:
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            feed = feedparser.parse(r.content)
        except Exception as e:  # un feed rotto non deve fermare gli altri
            log(f"[!] {name}: errore nel download ({e})")
            continue

        count = 0
        for e in feed.entries:
            dt = entry_datetime(e)
            link = clean_url(e.get("link"))
            title = clean_text(e.get("title"))
            if not dt or dt < cutoff or not link or not title:
                continue
            if SKIP_TITLE_RE.search(title):
                continue
            body = e.get("summary", "")
            if e.get("content"):
                body += " " + " ".join(c.get("value", "") for c in e["content"])
            text = clean_text(body)
            # categorie/tag dichiarati dal feed (<category> in RSS)
            feed_tags = []
            for t in e.get("tags", []) or []:
                term = clean_text(t.get("term"))
                if term and term.lower() not in {x.lower() for x in feed_tags}:
                    feed_tags.append(term)
            articles.append({"source": name, "title": title, "url": link,
                             "date": dt, "text": text, "tags": feed_tags})
            count += 1
        log(f"[+] {name}: {count} articoli nella finestra di {days} giorni")
    return articles


def report_tags(articles, top=12):
    """Diagnostica: per ogni fonte, i tag del feed più frequenti. Serve a capire
    quali feed espongono tag utili e a estendere le regole."""
    by_source = {}
    for a in articles:
        c = by_source.setdefault(a["source"], {})
        for t in a["tags"]:
            c[t] = c.get(t, 0) + 1
    for source, counts in by_source.items():
        n = sum(1 for a in articles if a["source"] == source)
        senza = sum(1 for a in articles if a["source"] == source and not a["tags"])
        top_tags = sorted(counts.items(), key=lambda kv: -kv[1])[:top]
        log(f"[tag] {source}: {n} articoli, {senza} senza tag")
        log("      " + (", ".join(f"{t} ({k})" for t, k in top_tags) or "(nessun tag)"))


# --------------------------------------------------------------------------
# Raggruppamento di articoli sulla stessa notizia
# --------------------------------------------------------------------------


def cluster_articles(articles):
    n = len(articles)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    cves = [set(c.upper() for c in CVE_RE.findall(a["title"] + " " + a["text"]))
            for a in articles]
    titles = [norm_title(a["title"]) for a in articles]

    for i in range(n):
        for j in range(i + 1, n):
            if articles[i]["source"] == articles[j]["source"]:
                continue
            # CVE in comune, ma solo se gli articoli non sono riepiloghi
            shared = cves[i] & cves[j]
            same_cve = bool(shared) and len(cves[i]) <= 3 and len(cves[j]) <= 3
            sm = difflib.SequenceMatcher(None, titles[i], titles[j])
            similar = sm.real_quick_ratio() > 0.6 and sm.ratio() >= 0.62
            if same_cve or similar:
                parent[find(i)] = find(j)

    groups = {}
    for i, a in enumerate(articles):
        groups.setdefault(find(i), []).append(a)
    return list(groups.values())


# --------------------------------------------------------------------------
# Classificazione a regole (fallback)
# --------------------------------------------------------------------------


def _hits(rx, text, cap):
    """Numero di termini *distinti* trovati (con tetto): la frequenza non conta,
    così un articolo lungo non batte un titolo chiaro."""
    if not text:
        return 0
    return min(cap, len({m.group(0).lower() for m in rx.finditer(text)}))


def category_scores(title, tags, body):
    """Punteggio per categoria. Pesi: tag del feed > titolo > corpo."""
    scores, title_strong = {}, {}
    for cat, rule in CATEGORY_RULES.items():
        t_strong = _hits(rule["strong"], title, 2)
        # Il titolo domina: un solo termine strong nel titolo (6) batte qualunque
        # combinazione nel solo corpo (max 5). I tag del feed sono un indizio, non
        # una prova: da soli (3) non bastano, devono essere confermati da titolo/corpo.
        scores[cat] = (6 * t_strong + 2 * _hits(rule["weak"], title, 2)
                       + 3 * _hits(rule["strong"], tags, 2) + 1 * _hits(rule["weak"], tags, 2)
                       + 2 * _hits(rule["strong"], body, 2) + 1 * _hits(rule["weak"], body, 1))
        title_strong[cat] = t_strong
    return scores, title_strong


def heuristic_category(title, tags, body, has_cves):
    scores, title_strong = category_scores(title, tags, body)
    if has_cves:
        scores["vuln"] += 1  # un CVE citato non basta: spesso è solo un riferimento
    best = max(PRIORITY, key=lambda c: (scores[c], -PRIORITY.index(c)))
    if scores[best] < MIN_SCORE:
        return "vuln" if has_cves else "general"
    if best in OVERRIDABLE:
        spec = [c for c in SPECIFIC_CATS if title_strong[c] and scores[c] >= MIN_SCORE]
        if spec:
            best = max(spec, key=lambda c: (scores[c], -PRIORITY.index(c)))
    return best


def collect_feed_tags(group):
    seen, out = set(), []
    for a in group:
        for t in a.get("tags", []):
            if t.lower() not in seen:
                seen.add(t.lower())
                out.append(t)
    return out


def heuristic_severity(text, category):
    low = text.lower()
    m = re.search(r"cvss[^0-9]{0,25}(\d{1,2}(?:\.\d)?)", low)
    cvss = float(m.group(1)) if m else None
    exploited = any(k in low for k in ("actively exploited", "exploited in the wild",
                                       "zero-day", "0-day", "in the wild",
                                       "sfruttat", "attivamente"))
    if (cvss and cvss >= 9.0) or (exploited and category == "vuln"):
        return "CRITICAL"
    technical = category not in ("general", "policy", "business")
    if (cvss and cvss >= 7.0) or category in ("ransomware", "breach", "apt", "supply-chain", "ics") \
            or (technical and ("critical" in low or "critica" in low
                               or "remote code execution" in low)):
        return "HIGH"
    if category in ("policy", "business"):
        return "LOW"
    return "MEDIUM"


def excerpt(text, limit=420):
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    return cut[:end + 1] if end > 150 else cut.rsplit(" ", 1)[0] + "…"


def heuristic_item(group, combined):
    cves = sorted(set(c.upper() for c in CVE_RE.findall(combined)))
    feed_tags = collect_feed_tags(group)
    # la categoria si decide sull'intero cluster: titoli, tag e testi di tutte le testate
    cat = heuristic_category(" | ".join(a["title"] for a in group),
                             " | ".join(feed_tags),
                             " ".join(a["text"] for a in group),
                             bool(cves))
    best = max(group, key=lambda a: len(a["text"]))
    tags = [t for t in feed_tags if t.lower() not in GENERIC_TAGS and len(t) <= 40][:6]
    return {
        "title": group[0]["title"],
        "category": cat,
        "severity": heuristic_severity(combined, cat),
        "summary": excerpt(best["text"]) or group[0]["title"],
        "tags": tags or [cat],
    }


# --------------------------------------------------------------------------
# Arricchimento con Claude (opzionale)
# --------------------------------------------------------------------------

LLM_SYSTEM = (
    "Sei un analista di cybersecurity che cura un database di notizie in italiano. "
    "Ricevi uno o più articoli sulla stessa notizia. Rispondi SOLO con un oggetto JSON, "
    "senza testo prima o dopo e senza backtick, con queste chiavi: "
    '"title" (titolo breve in italiano, max 120 caratteri), '
    '"summary" (2-4 frasi in italiano, scritte con parole tue: non copiare frasi dagli '
    "articoli; includi solo fatti presenti nei testi e segnala se qualcosa è solo ipotizzato), "
    f'"category" (uno tra {CATEGORIES}), '
    f'"severity" (uno tra {SEVERITIES}: CRITICAL se sfruttamento attivo/zero-day grave o impatto '
    "molto esteso, HIGH se grave, MEDIUM se rilevante, LOW se informativa), "
    '"tags" (da 2 a 6 etichette brevi: prodotti, gruppi, aziende, paesi). '
    "Non inventare CVE né dettagli assenti dai testi."
)


def llm_item(group, api_key):
    parts = []
    for a in group:
        parts.append(f"[{a['source']}] {a['title']}\n{a['text'][:1800]}")
    payload = {
        "model": LLM_MODEL,
        "max_tokens": 700,
        "system": LLM_SYSTEM,
        "messages": [{"role": "user", "content": "\n\n---\n\n".join(parts)}],
    }
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01",
               "content-type": "application/json"}
    for attempt in range(4):
        try:
            r = requests.post("https://api.anthropic.com/v1/messages",
                              headers=headers, json=payload, timeout=90)
            if r.status_code in (429, 500, 502, 503, 529):
                time.sleep(2 ** attempt * 2)
                continue
            r.raise_for_status()
            text = "".join(b.get("text", "") for b in r.json().get("content", []))
            data = json.loads(text[text.index("{"): text.rindex("}") + 1])
            if data.get("category") not in CATEGORIES or data.get("severity") not in SEVERITIES:
                raise ValueError("categoria/severità non valide")
            tags = [str(t).strip() for t in data.get("tags", []) if str(t).strip()][:6]
            return {
                "title": str(data["title"]).strip(),
                "category": data["category"],
                "severity": data["severity"],
                "summary": str(data["summary"]).strip(),
                "tags": tags or [data["category"]],
            }
        except Exception as e:
            log(f"    LLM tentativo {attempt + 1} fallito: {e}")
            time.sleep(1.5)
    return None


# --------------------------------------------------------------------------
# Costruzione del database
# --------------------------------------------------------------------------


def load_cache(path):
    """Mappa url -> item da un news_db.json precedente, per non rielaborare
    (e non pagare) notizie già trattate."""
    try:
        with open(path, encoding="utf-8") as f:
            db = json.load(f)
        cache = {}
        for it in db.get("items", []):
            for s in it.get("sources", []):
                cache[s["url"]] = it
        return cache
    except Exception:
        return {}


def build_items(groups, api_key, cache, max_items):
    items = []
    # le notizie coperte da più testate prima, poi le più recenti
    groups.sort(key=lambda g: (-len({a["source"] for a in g}), -max(a["date"] for a in g).timestamp()))
    groups = groups[:max_items]

    for k, group in enumerate(groups, 1):
        urls = {a["url"] for a in group}
        combined = " ".join(a["title"] + " " + a["text"] for a in group)
        cves = sorted(set(c.upper() for c in CVE_RE.findall(combined)))

        cached = next((cache[u] for u in urls if u in cache), None)
        if cached and urls <= {s["url"] for s in cached["sources"]}:
            base = {k2: cached[k2] for k2 in ("title", "category", "severity", "summary", "tags")}
        else:
            base = llm_item(group, api_key) if api_key else None
            if base is None:
                base = heuristic_item(group, combined)
            if api_key:
                log(f"    [{k}/{len(groups)}] {base['title'][:80]}")

        seen, sources = set(), []
        for a in sorted(group, key=lambda a: a["date"]):
            if a["url"] not in seen:
                seen.add(a["url"])
                sources.append({"title": a["source"], "url": a["url"]})

        items.append({
            "id": "",  # assegnato dopo l'ordinamento
            "published": min(a["date"] for a in group).strftime("%Y-%m-%d"),
            "title": base["title"],
            "category": base["category"],
            "severity": base["severity"],
            "summary": base["summary"],
            "tags": base["tags"],
            "cves": cves,
            "sources": sources,
        })

    items.sort(key=lambda i: (i["published"], -SEV_RANK[i["severity"]]), reverse=True)
    # a parità di data: severità più alta prima
    items.sort(key=lambda i: (i["published"], -SEV_RANK[i["severity"]]), reverse=True)
    counters = {}
    for it in items:
        counters[it["published"]] = counters.get(it["published"], 0) + 1
        it["id"] = f"{it['published']}-{counters[it['published']]:03d}"
    return items


def validate(db, schema_path):
    try:
        import jsonschema
    except ImportError:
        log("[i] jsonschema non installato: validazione saltata (pip install jsonschema)")
        return
    if not os.path.exists(schema_path):
        log(f"[i] {schema_path} non trovato: validazione saltata")
        return
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)
    jsonschema.validate(db, schema)
    log("[✓] news_db.json valido rispetto allo schema")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=7, help="finestra in giorni (default 7)")
    ap.add_argument("--out", default="news_db.json", help="file di output")
    ap.add_argument("--schema", default="news_schema.json", help="schema per la validazione")
    ap.add_argument("--max-items", type=int, default=60, help="numero massimo di notizie")
    ap.add_argument("--no-llm", action="store_true", help="non usare l'API di Claude")
    ap.add_argument("--show-tags", action="store_true",
                    help="stampa i tag più frequenti di ogni feed (diagnostica) ed esce")
    args = ap.parse_args()

    api_key = None if args.no_llm else os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        log(f"[i] Modalità LLM attiva (modello {LLM_MODEL})")
    else:
        log("[i] Modalità a regole: titoli e riassunti resteranno nella lingua originale")

    articles = fetch_articles(args.days)
    if not articles:
        log("Nessun articolo scaricato: file non modificato.")
        sys.exit(1)

    if args.show_tags:
        report_tags(articles)
        return

    groups = cluster_articles(articles)
    log(f"[i] {len(articles)} articoli -> {len(groups)} notizie distinte")

    # Senza LLM la classificazione è gratuita e deterministica: niente cache, così
    # ogni esecuzione applica le regole correnti anche alle notizie già presenti.
    cache = load_cache(args.out) if api_key else {}
    items = build_items(groups, api_key, cache, args.max_items)
    db = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": args.days,
        "items": items,
    }
    validate(db, args.schema)

    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, args.out)
    log(f"[✓] Scritte {len(items)} notizie in {args.out}")


if __name__ == "__main__":
    main()
