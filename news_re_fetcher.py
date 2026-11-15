#!/usr/bin/env python3
"""
news_re_fetcher.py - Raccoglie report tecnici (reverse engineering, malware
analysis, vulnerability research, low level) da blog di ricerca e aggregatori
e genera news_re_db.json per news_re.html.

Differenze rispetto a news_fetcher.py:
  - fonti solo tecniche (blog di ricerca, vendor research, r/ReverseEngineering, lobste.rs)
  - filtro di rilevanza: i post non tecnici vengono scartati
  - il titolo resta quello originale (cosi' si puo' cercare); il riassunto e'
    in italiano e dice cosa si impara (con LLM) oppure e' un estratto (senza)
  - il database e' un archivio: le voci restano per --keep-days giorni
    anche se escono dal feed

Dipendenze:
    pip install feedparser requests

Modalita' LLM (opzionale):
    export ANTHROPIC_API_KEY=sk-ant-...
    Le voci gia' arricchite finiscono in cache: a ogni run si pagano solo le nuove.

Uso:
    python news_re_fetcher.py                  # ultimi 30 giorni -> news_re_db.json
    python news_re_fetcher.py --days 120       # primo riempimento dell'archivio
    python news_re_fetcher.py --no-llm
"""

import argparse
import hashlib
import html
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
import requests

# --------------------------------------------------------------------------
# Configurazione
# --------------------------------------------------------------------------

# min    = punteggio minimo di rilevanza per tenere il post
#          (1 = blog tecnico, 3-4 = blog con mix tecnico/marketing)
# agg    = aggregatore: l'URL dell'articolo e' esterno, la fonte mostrata e' il dominio
# reddit = il link all'articolo va estratto dal corpo del post
# default= topic usato se nessuna parola chiave matcha
# L'ordine conta: in caso di stesso articolo su piu' feed vince il primo.
# Gli URL non sono stati verificati uno a uno: se un feed cambia indirizzo
# basta correggerlo qui (il log mostra gli errori di download).
FEEDS = [
    # --- blog di ricerca ---
    {"name": "Project Zero",   "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "min": 1},
    {"name": "Trail of Bits",  "url": "https://blog.trailofbits.com/feed/", "min": 1},
    {"name": "Quarkslab",      "url": "https://blog.quarkslab.com/feeds/all.rss.xml", "min": 1},
    {"name": "Synacktiv",      "url": "https://www.synacktiv.com/feed.xml", "min": 1},
    {"name": "Binarly",        "url": "https://www.binarly.io/blog/rss.xml", "min": 1},
    {"name": "ZDI",            "url": "https://www.zerodayinitiative.com/blog?format=rss", "min": 1},
    {"name": "watchTowr",      "url": "https://labs.watchtowr.com/rss/", "min": 1},
    {"name": "Doyensec",       "url": "https://blog.doyensec.com/atom.xml", "min": 1},
    {"name": "Objective-See",  "url": "https://objective-see.org/rss.xml", "min": 1},
    {"name": "Elastic Labs",   "url": "https://www.elastic.co/security-labs/rss/feed.xml", "min": 1},
    # --- vendor research (mix tecnico/marketing: soglia piu' alta) ---
    {"name": "Securelist",     "url": "https://securelist.com/feed/", "min": 3},
    {"name": "ESET",           "url": "https://www.welivesecurity.com/en/rss/feed/", "min": 4},
    {"name": "Talos",          "url": "https://blog.talosintelligence.com/rss/", "min": 3},
    {"name": "Unit 42",        "url": "https://unit42.paloaltonetworks.com/feed/", "min": 3},
    {"name": "Check Point",    "url": "https://research.checkpoint.com/feed/", "min": 3},
    {"name": "Mandiant",       "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", "min": 3},
    {"name": "Sophos X-Ops",   "url": "https://news.sophos.com/en-us/category/threat-research/feed/", "min": 3},
    # --- aggregatori ---
    {"name": "lobste.rs",      "url": "https://lobste.rs/t/reversing.rss", "min": 0, "agg": True, "default": "reverse"},
    {"name": "lobste.rs",      "url": "https://lobste.rs/t/security.rss", "min": 4, "agg": True},
    {"name": "r/ReverseEngineering", "url": "https://www.reddit.com/r/ReverseEngineering/.rss",
     "min": 0, "agg": True, "reddit": True, "default": "reverse"},
    {"name": "r/netsec",       "url": "https://www.reddit.com/r/netsec/.rss",
     "min": 4, "agg": True, "reddit": True},
]

TOPICS = ["reverse", "malware", "vuln", "exploit", "firmware", "kernel", "mobile"]

USER_AGENT = "Mozilla/5.0 (compatible; news-re-fetcher/1.0; +personal-use)"
HTTP_TIMEOUT = 25
LLM_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TAG_RE = re.compile(r"<[^>]+>")
HREF_RE = re.compile(r'href="([^"]+)"', re.I)
BOILERPLATE_RE = re.compile(r"\s*(?:The post|L'articolo)\s.+?(?:appeared first on|proviene da).*$", re.I)
SKIP_TITLE_RE = re.compile(
    r"webinar|podcast|newsletter|weekly|week in review|threatsday|recap|whitepaper|"
    r"press release|\bannounces?\b|\bpartnership\b|\braises\b|\bpricing\b|sponsored|"
    r"\btop \d+\b|\bpredictions?\b|\bsurvey\b|\bhiring\b", re.I)
SKIP_LINK_DOMAINS = ("reddit.com", "redd.it", "imgur.com", "youtube.com", "youtu.be", "twitter.com", "x.com")

# Parole chiave per topic. Ogni pattern e' ancorato a parola intera
# (?<!\w)...(?!\w): usa \w* per gli stem ("decompil\w*"). Niente gruppi
# catturanti, solo (?:...).
TOPIC_KW = {
    "reverse": [
        r"reverse[- ]engineer\w*", r"reversing", r"disassembl\w*", r"decompil\w*", r"ghidra",
        r"ida pro", r"binary ninja", r"radare2?", r"rizin", r"unpack\w*", r"deobfuscat\w*",
        r"obfuscat\w*", r"crackme", r"shellcode", r"assembly", r"x86(?:-64)?", r"arm64",
        r"aarch64", r"elf", r"debugg\w*", r"symbolic execution", r"angr", r"frida",
        r"emulat\w*", r"anti-debug\w*", r"binary analysis", r"control[- ]flow", r"decod\w*",
    ],
    "malware": [
        r"malware", r"trojan", r"backdoor", r"implant", r"loader", r"dropper", r"stealer",
        r"botnet", r"rootkit", r"bootkit", r"ransomware", r"c2", r"command[- ]and[- ]control",
        r"yara", r"sandbox", r"persistence", r"payload", r"threat actor", r"malicious",
    ],
    "vuln": [
        r"vulnerabilit\w*", r"cve-\d{4}-\d{4,7}", r"zero[- ]day", r"0-day", r"root cause",
        r"patch diff\w*", r"bindiff", r"fuzz\w*", r"use[- ]after[- ]free", r"out[- ]of[- ]bounds",
        r"buffer overflow", r"integer overflow", r"type confusion", r"race condition",
        r"memory corruption", r"memory safety", r"sanitizers?", r"cvss", r"rce",
        r"remote code execution", r"privilege escalation", r"lpe", r"sandbox escape",
        r"auth(?:entication)? bypass",
    ],
    "exploit": [
        r"exploit\w*", r"poc", r"rop", r"heap spray\w*", r"heap", r"jop", r"aslr", r"kaslr",
        r"cfi", r"primitives?", r"gadgets?", r"stack canar\w*", r"got overwrite", r"format string",
        r"jailbreak\w*", r"mitigations?",
    ],
    "firmware": [
        r"firmware", r"uefi", r"bios", r"bootloader", r"secure boot", r"embedded", r"iot",
        r"router", r"uart", r"jtag", r"spi flash", r"baseband", r"fpga", r"side[- ]channel",
        r"binwalk", r"trustzone", r"tpm", r"smm", r"bmc",
    ],
    "kernel": [
        r"kernel", r"drivers?", r"ebpf", r"bpf", r"hypervisor", r"syscalls?", r"windows internals",
        r"ntdll", r"etw", r"hooking", r"ring ?0", r"vdso", r"io_uring", r"ptrace", r"seccomp",
        r"page tables?", r"mmu", r"win32k", r"ntoskrnl", r"llvm", r"glibc", r"memory allocator",
        r"jit", r"linux", r"edr",
    ],
    "mobile": [
        r"android", r"ios", r"apk", r"dex", r"smali", r"jadx", r"magisk", r"objective-c",
        r"xnu", r"macos", r"mach-o", r"arm",
    ],
}
TOPIC_RE = {t: re.compile(r"(?<!\w)(?:" + "|".join(p) + r")(?!\w)") for t, p in TOPIC_KW.items()}
# termini troppo generici per essere buoni tag
GENERIC = {"linux", "driver", "drivers", "embedded", "heap", "payload", "malicious", "router",
           "assembly", "arm", "ios", "elf", "decod", "mitigation", "mitigations", "sandbox"}

# --------------------------------------------------------------------------
# Utilita'
# --------------------------------------------------------------------------


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def clean_text(raw):
    if not raw:
        return ""
    txt = html.unescape(TAG_RE.sub(" ", raw))
    txt = re.sub(r"\s+", " ", txt).strip()
    return BOILERPLATE_RE.sub("", txt).strip()


def clean_url(url):
    """https, niente tracking/fragment/slash finale. None se non e' un URL di articolo."""
    if not url:
        return None
    p = urlsplit(html.unescape(url.strip()))
    if p.scheme == "http":
        p = p._replace(scheme="https")
    if p.scheme != "https" or not p.netloc or p.path in ("", "/"):
        return None
    q = [(k, v) for k, v in parse_qsl(p.query)
         if not k.lower().startswith("utm_") and k.lower() not in ("fbclid", "gclid", "ref")]
    path = p.path.rstrip("/") or "/"
    return urlunsplit((p.scheme, p.netloc, path, urlencode(q), ""))


def entry_datetime(entry):
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        t = entry.get(key)
        if t:
            return datetime(*t[:6], tzinfo=timezone.utc)
    return None


def external_link(raw_html):
    """Reddit: primo href del corpo che non punta a reddit/immagini/video."""
    for href in HREF_RE.findall(raw_html or ""):
        url = clean_url(href)
        if url and not any(d in urlsplit(url).netloc for d in SKIP_LINK_DOMAINS):
            return url
    return None


def domain_label(url):
    host = urlsplit(url).netloc.lower()
    for pre in ("www.", "blog."):
        if host.startswith(pre):
            host = host[len(pre):]
    return host


def excerpt(text, limit=420):
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    return cut[:end + 1] if end > 150 else cut.rsplit(" ", 1)[0] + "…"


# --------------------------------------------------------------------------
# Download feed
# --------------------------------------------------------------------------


def fetch_entries(days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for f in FEEDS:
        try:
            r = requests.get(f["url"], headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            feed = feedparser.parse(r.content)
        except Exception as ex:  # un feed rotto non ferma gli altri
            log(f"[!] {f['name']}: errore nel download ({ex})")
            continue

        kept = 0
        for e in feed.entries:
            dt = entry_datetime(e)
            title = clean_text(e.get("title"))
            if not dt or dt < cutoff or not title or SKIP_TITLE_RE.search(title):
                continue
            contents = [c.get("value", "") for c in (e.get("content") or [])]
            raw = e.get("summary", "") + " " + " ".join(contents)

            disc = None
            if f.get("reddit"):
                link = external_link(raw)          # niente link esterno = self-post: scartato
                disc = clean_url(e.get("link"))
                text, words = "", 0                # il corpo di Reddit e' solo "submitted by..."
            else:
                link = clean_url(e.get("link"))
                if f.get("agg"):
                    disc = clean_url(e.get("comments"))
                text = clean_text(raw)
                words = len(clean_text(" ".join(contents)).split()) if contents else 0
            if not link:
                continue

            out.append({"name": f["name"], "agg": bool(f.get("agg")), "min": f["min"],
                        "default": f.get("default"), "title": title, "url": link,
                        "date": dt, "text": text, "words": words, "disc": disc})
            kept += 1
        log(f"[+] {f['name']}: {kept} voci nella finestra di {days} giorni")
    return out


def group_by_url(entries):
    groups = {}
    for e in entries:
        groups.setdefault(e["url"], []).append(e)
    return groups


# --------------------------------------------------------------------------
# Rilevanza e classificazione a regole
# --------------------------------------------------------------------------


def analyze(title, text):
    """Punteggio per topic: 3 per ogni match nel titolo, 1 per match nel testo (max 6).
    Restituisce (scores, Counter dei termini trovati)."""
    tl, bl = title.lower(), text[:8000].lower()
    scores, terms = {}, Counter()
    for t, rx in TOPIC_RE.items():
        th = [m.group(0) for m in rx.finditer(tl)]
        bh = [m.group(0) for m in rx.finditer(bl)]
        scores[t] = 3 * len(th) + min(len(bh), 6)
        terms.update(th + th + bh)
    return scores, terms


def heuristic(group, scores, terms, total):
    if total:
        topic = max(TOPICS, key=lambda t: (scores[t], -TOPICS.index(t)))
    else:
        topic = next((e["default"] for e in group if e.get("default")), "reverse")
    tags = []
    for w, _ in terms.most_common(14):
        w = re.sub(r"\s+", " ", w.replace("-", " ")).strip()
        if w not in GENERIC and not CVE_RE.fullmatch(w) and w not in tags:
            tags.append(w)
    best = max(group, key=lambda e: len(e["text"]))
    return {"summary": excerpt(best["text"]) or group[0]["title"],
            "topic": topic, "tags": tags[:5] or [topic]}


# --------------------------------------------------------------------------
# Arricchimento con Claude (opzionale)
# --------------------------------------------------------------------------

LLM_SYSTEM = (
    "Sei un reverse engineer che cura una raccolta di report tecnici per chi vuole imparare. "
    "Ricevi un articolo (titolo ed eventuale estratto). Rispondi SOLO con un oggetto JSON, "
    "senza testo prima o dopo e senza backtick, con queste chiavi: "
    '"summary" (2-3 frasi in italiano, con parole tue, senza copiare frasi dal testo: di cosa '
    "tratta e cosa si impara, cioe' tecnica, strumenti, target analizzato; usa solo fatti presenti "
    "nel testo; se manca l'estratto limitati a quanto dice il titolo), "
    f'"topic" (uno tra {TOPICS}: reverse=reverse engineering/tool, malware=analisi malware, '
    "vuln=vulnerability research, exploit=exploit development, firmware=firmware/hardware/embedded, "
    "kernel=internals OS/low level, mobile=Android/iOS), "
    '"tags" (da 2 a 6 etichette brevi: strumenti, tecniche, prodotti, famiglie di malware). '
    "Non inventare CVE ne' dettagli assenti dal testo."
)


def llm_enrich(group, api_key):
    parts = [f"[{e['name']}] {e['title']}\n{e['text'][:1800]}" for e in group[:2]]
    payload = {"model": LLM_MODEL, "max_tokens": 500, "system": LLM_SYSTEM,
               "messages": [{"role": "user", "content": "\n\n---\n\n".join(parts)}]}
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
            if data.get("topic") not in TOPICS:
                raise ValueError("topic non valido")
            tags = [str(t).strip() for t in data.get("tags", []) if str(t).strip()][:6]
            return {"summary": str(data["summary"]).strip(), "topic": data["topic"],
                    "tags": tags or [data["topic"]]}
        except Exception as ex:
            log(f"    LLM tentativo {attempt + 1} fallito: {ex}")
            time.sleep(1.5)
    return None


# --------------------------------------------------------------------------
# Costruzione del database
# --------------------------------------------------------------------------


def load_db(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f).get("items", [])
    except Exception:
        return []


def build_sources(group):
    first = group[0]
    label = domain_label(first["url"]) if first["agg"] else first["name"]
    srcs = [{"title": label, "url": first["url"]}]
    seen = {first["url"]}
    for e in group:
        if e["disc"] and e["disc"] not in seen:
            seen.add(e["disc"])
            srcs.append({"title": f"{e['name']} (discussione)", "url": e["disc"]})
    return label, srcs


def build_items(groups, api_key, cache, max_items):
    cands = []
    for group in groups.values():
        text = " ".join(e["text"] for e in group) + " " + " ".join(e["title"] for e in group[1:])
        scores, terms = analyze(group[0]["title"], text)
        total = sum(scores.values())
        if total < min(e["min"] for e in group):
            continue
        cands.append((group, scores, terms, total))
    cands.sort(key=lambda c: min(e["date"] for e in c[0]), reverse=True)
    cands = cands[:max_items]

    items = []
    for k, (group, scores, terms, total) in enumerate(cands, 1):
        url = group[0]["url"]
        combined = group[0]["title"] + " " + " ".join(e["text"] for e in group)
        cached = cache.get(url)
        if cached and (cached.get("by") == "llm" or not api_key):
            base = {x: cached[x] for x in ("summary", "topic", "tags")}
            by = cached.get("by", "rules")
        else:
            base = llm_enrich(group, api_key) if api_key else None
            by = "llm"
            if base is None:
                base, by = heuristic(group, scores, terms, total), "rules"
            if api_key:
                log(f"    [{k}/{len(cands)}] {group[0]['title'][:80]}")

        label, sources = build_sources(group)
        words = max(e["words"] for e in group)
        items.append({
            "id": hashlib.sha1(url.encode()).hexdigest()[:10],
            "published": min(e["date"] for e in group).strftime("%Y-%m-%d"),
            "title": group[0]["title"],
            "topic": base["topic"],
            "source": label,
            "summary": base["summary"],
            "tags": base["tags"],
            "cves": sorted({c.upper() for c in CVE_RE.findall(combined)})[:8],
            "read_min": round(words / 220) if words >= 400 else None,
            "by": by,
            "sources": sources,
        })
    return items


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=30, help="finestra di download in giorni (default 30)")
    ap.add_argument("--keep-days", type=int, default=180, help="quanto tenere le voci in archivio (default 180)")
    ap.add_argument("--out", default="news_re_db.json")
    ap.add_argument("--max-items", type=int, default=150, help="massimo di voci elaborate per run")
    ap.add_argument("--no-llm", action="store_true")
    args = ap.parse_args()

    api_key = None if args.no_llm else os.environ.get("ANTHROPIC_API_KEY")
    log(f"[i] Modalita' LLM attiva ({LLM_MODEL})" if api_key
        else "[i] Modalita' a regole: riassunti = estratto in lingua originale")

    entries = fetch_entries(args.days)
    if not entries:
        log("Nessuna voce scaricata: file non modificato.")
        sys.exit(1)

    old = load_db(args.out)
    cache = {s["url"]: it for it in old for s in it.get("sources", [])[:1]}

    groups = group_by_url(entries)
    items = build_items(groups, api_key, cache, args.max_items)
    log(f"[i] {len(entries)} voci -> {len(groups)} articoli -> {len(items)} rilevanti")

    # archivio: tieni le vecchie voci non rivedute in questo run
    fresh_ids = {i["id"] for i in items}
    keep_cut = (datetime.now(timezone.utc) - timedelta(days=args.keep_days)).strftime("%Y-%m-%d")
    retained = [it for it in old if it.get("id") not in fresh_ids and it.get("published", "") >= keep_cut]
    items += retained
    items.sort(key=lambda i: (i["published"], i["topic"]), reverse=True)

    db = {"updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
          "keep_days": args.keep_days, "items": items}
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, args.out)
    log(f"[✓] Scritte {len(items)} voci in {args.out} ({len(retained)} dall'archivio)")


if __name__ == "__main__":
    main()
