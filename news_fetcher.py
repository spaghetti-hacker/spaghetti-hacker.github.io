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
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Red Hot Cyber", "https://www.redhotcyber.com/feed/"),
    ("Cybersecurity360", "https://www.cybersecurity360.it/feed/"),
    ("Securityinfo.it", "https://www.securityinfo.it/feed/"),
]

CATEGORIES = ["ransomware", "vuln", "breach", "apt", "malware",
              "supply-chain", "ics", "policy", "business"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

USER_AGENT = "Mozilla/5.0 (compatible; news-fetcher/1.0; +personal-use)"
HTTP_TIMEOUT = 25
LLM_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TAG_RE = re.compile(r"<[^>]+>")
SKIP_TITLE_RE = re.compile(
    r"weekly recap|newsletter|podcast|webinar|\bwhitepaper\b|sponsored|"
    r"giveaway|\bdeal(s)?\b|\bsconti\b|\bcorso\b", re.I)

# Parole chiave per il fallback di classificazione (EN + IT)
CATEGORY_KEYWORDS = {
    "ics": ["scada", "industrial control", "plc", "ics ", "operational technology",
            "sistemi industriali", "ot security", "hmi"],
    "supply-chain": ["supply chain", "supply-chain", "npm", "pypi", "malicious package",
                     "github actions", "catena di fornitura", "dependency", "rubygems",
                     "pacchetti malevoli", "vs code extension"],
    "ransomware": ["ransomware", "ransom ", "extortion gang", "double extortion",
                   "lockbit", "estorsione", "riscatto"],
    "apt": ["apt", "nation-state", "state-sponsored", "lazarus", "espionage",
            "threat actor linked", "cyber espionage", "spionaggio", "sponsorizzat"],
    "breach": ["data breach", "breach", "data leak", "leaked", "stolen data",
               "exposed database", "violazione dei dati", "data exposure",
               "esposti", "furto di dati", "dati rubati"],
    "vuln": ["vulnerability", "vulnerabilit", "patch", "zero-day", "0-day",
             "remote code execution", "rce", "privilege escalation", "cvss",
             "flaw", "exploit", "aggiornamento di sicurezza"],
    "malware": ["malware", "trojan", "botnet", "stealer", "backdoor", "loader",
                "phishing", "infostealer", "spyware", "rat ", "campagna"],
    "policy": ["regulation", "nis2", "gdpr", "law ", "legislation", "sanction",
               "arrest", "europol", "indicted", "fine ", "normativa", "garante",
               "legge", "acn ", "cisa", "extradit", "sentenced", "condannat"],
    "business": ["acquire", "acquisition", "funding", "raises", "ipo", "series a",
                 "series b", "layoffs", "acquisizione", "finanziamento", "partnership"],
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
            articles.append({"source": name, "title": title, "url": link,
                             "date": dt, "text": text})
            count += 1
        log(f"[+] {name}: {count} articoli nella finestra di {days} giorni")
    return articles


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


def heuristic_category(text, has_cves):
    low = " " + text.lower() + " "
    scores = {c: sum(low.count(k) for k in kws) for c, kws in CATEGORY_KEYWORDS.items()}
    best = max(scores.items(), key=lambda kv: (kv[1], -CATEGORIES.index(kv[0])))
    if best[1] == 0:
        return "vuln" if has_cves else "malware"
    return best[0]


def heuristic_severity(text, category):
    low = text.lower()
    m = re.search(r"cvss[^0-9]{0,25}(\d{1,2}(?:\.\d)?)", low)
    cvss = float(m.group(1)) if m else None
    exploited = any(k in low for k in ("actively exploited", "exploited in the wild",
                                       "zero-day", "0-day", "in the wild",
                                       "sfruttat", "attivamente"))
    if (cvss and cvss >= 9.0) or (exploited and category == "vuln"):
        return "CRITICAL"
    if (cvss and cvss >= 7.0) or category in ("ransomware", "breach", "apt", "supply-chain", "ics") \
            or "critical" in low or "critica" in low or "remote code execution" in low:
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
    cat = heuristic_category(combined, bool(cves))
    best = max(group, key=lambda a: len(a["text"]))
    tags = sorted({c for c in cves[:0]})  # nessun tag affidabile senza LLM
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

    groups = cluster_articles(articles)
    log(f"[i] {len(articles)} articoli -> {len(groups)} notizie distinte")

    items = build_items(groups, api_key, load_cache(args.out), args.max_items)
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
