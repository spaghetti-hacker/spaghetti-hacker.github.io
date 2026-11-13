#!/usr/bin/env python3
"""
cti_update.py - genera cti_db.json per cti.html

Fonti:
  1. MITRE ATT&CK (STIX, GitHub)  -> profili degli attori e tecniche (TTP)
  2. Feed RSS/Atom (FEEDS)         -> ultima attivita degli attori + campagne "auto"
  3. cti_curated.json (a mano)     -> correzioni agli attori, attori extra, campagne

Solo libreria standard. Uso tipico (cron ogni poche ore):
    python3 cti_update.py
Opzioni utili:
    --offline      non usa la rete, solo cache MITRE e file locali
    --days N       finestra di giorni per le campagne auto (default 90)
    -v             piu dettagli

Il browser non contatta mai le fonti: legge solo cti_db.json (CSP invariata).
"""
import argparse
import copy
import email.utils
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

# ───────────────────────── configurazione ─────────────────────────

MITRE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
             "master/enterprise-attack/enterprise-attack.json")

WINDOW_DAYS = 90
MAX_TTPS_PER_ACTOR = 12
MAX_AUTO_CAMPAIGNS = 60
MAX_ACTOR_SOURCES = 3
CACHE_MAX_AGE_H = 24 * 7

# Attori MITRE da seguire (nome o alias). Si aggiungono anche quelli la cui
# descrizione MITRE cita l'Italia.
WATCH_ACTORS = [
    "APT28", "APT29", "Sandworm Team", "Lazarus Group", "Turla", "Kimsuky",
    "APT41", "MuddyWater", "Gamaredon Group", "FIN7", "Scattered Spider",
    "Volt Typhoon",
]

# Feed. scope: "IT" = fonte italiana; trusted: una citazione di un attore basta
# per creare una campagna anche senza riferimenti all'Italia;
# all_items: ogni articolo diventa una voce in CAMPAIGNS (utile per CERT-AgID).
# Verifica gli URL: alcuni siti cambiano percorso. Puoi sostituire l'intero
# elenco con la chiave "feeds" in cti_curated.json.
FEEDS = [
    {"name": "CERT-AgID",        "url": "https://cert-agid.gov.it/feed/",                           "scope": "IT",     "all_items": True},
    {"name": "Red Hot Cyber",    "url": "https://www.redhotcyber.com/feed/",                        "scope": "IT"},
    {"name": "CISA",             "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",    "scope": "GLOBAL", "trusted": True},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/",                   "scope": "GLOBAL"},
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews",              "scope": "GLOBAL"},
]

ITALY_RE = re.compile(
    r"\b(italia|italy|italian[oiae]?|italiani|italiane|csirt italia|agenzia per la cybersicurezza)\b", re.I)

TACTIC_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
    "resource-development", "reconnaissance",
]

# ───────────────────────── utilita ─────────────────────────


def log(*a):
    print("[cti]", *a, file=sys.stderr)


def load_json(path, default, strict=False):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, OSError) as e:
        log(f"{path}: non leggibile ({e})")
        if strict:
            sys.exit(2)
        return default


def write_json_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "cti-update/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def strip_html(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def clean_mitre_text(s):
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    return re.sub(r"\s+", " ", s).strip()


def shorten(s, n):
    s = s.strip()
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "..."


def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        d = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError):
        d = None
    if d is None:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def day(d):
    return d.strftime("%Y-%m-%d")


def as_list(x):
    return [str(i) for i in x] if isinstance(x, list) else []


# ───────────────────────── MITRE ATT&CK ─────────────────────────


def get_mitre(args):
    cache = os.path.join(args.cache_dir, "enterprise-attack.json")
    have = os.path.exists(cache)
    fresh = have and (time.time() - os.path.getmtime(cache)) < CACHE_MAX_AGE_H * 3600
    if fresh or (args.offline and have):
        path = cache
    elif args.offline:
        log("offline e nessuna cache MITRE")
        return None
    else:
        try:
            log("scarico MITRE ATT&CK (puo richiedere un po')...")
            raw = fetch(args.mitre_url, timeout=180)
            os.makedirs(args.cache_dir, exist_ok=True)
            with open(cache + ".tmp", "wb") as f:
                f.write(raw)
            os.replace(cache + ".tmp", cache)
            path = cache
        except Exception as e:  # rete, TLS, URL, disco
            log(f"download MITRE fallito: {e}")
            if not have:
                return None
            log("uso la cache scaduta")
            path = cache
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log(f"cache MITRE non valida: {e}")
        return None


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return ""


def ext_url(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("url"):
            return r["url"]
    return ""


def parse_mitre(data):
    groups, techs, soft, rels = {}, {}, {}, []
    for o in data.get("objects", []):
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        t = o.get("type")
        if t == "intrusion-set":
            groups[o["id"]] = o
        elif t == "attack-pattern":
            techs[o["id"]] = o
        elif t in ("malware", "tool"):
            soft[o["id"]] = o
        elif t == "relationship" and o.get("relationship_type") == "uses":
            rels.append(o)

    by_ext = {ext_id(o): o for o in techs.values() if ext_id(o)}
    index = {}  # id padre -> {id, name, tactic, url}
    for eid, o in by_ext.items():
        if "." in eid:
            continue
        phases = [p["phase_name"] for p in o.get("kill_chain_phases", []) if "phase_name" in p]
        phases.sort(key=lambda p: TACTIC_ORDER.index(p) if p in TACTIC_ORDER else 99)
        index[eid] = {"id": eid, "name": o.get("name", ""),
                      "tactic": phases[0] if phases else "", "url": ext_url(o)}

    g_ttps, g_tools = {}, {}
    for r in rels:
        s, t = r.get("source_ref"), r.get("target_ref")
        if s not in groups:
            continue
        if t in techs:
            eid = ext_id(techs[t]).split(".")[0]
            if eid in index:
                g_ttps.setdefault(s, set()).add(eid)
        elif t in soft:
            g_tools.setdefault(s, set()).add(soft[t].get("name", ""))
    return groups, index, g_ttps, g_tools


def pick_ttps(ids, index):
    def key(i):
        t = index[i]["tactic"]
        return (TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99, i)
    return sorted((i for i in ids if i in index), key=key)[:MAX_TTPS_PER_ACTOR]


def actors_from_mitre(data, overrides):
    groups, index, g_ttps, g_tools = parse_mitre(data)
    watch = {w.lower() for w in WATCH_ACTORS}
    actors = []
    for gid, g in groups.items():
        name = g.get("name", "")
        aliases = [a for a in g.get("aliases", []) if a != name]
        desc = clean_mitre_text(g.get("description", ""))
        listed = bool({name.lower(), *(a.lower() for a in aliases)} & watch)
        mentions_italy = bool(ITALY_RE.search(desc))
        ov = overrides.get(name, {})
        if not (listed or mentions_italy or ov):
            continue
        a = {
            "id": ext_id(g) or gid,
            "name": name,
            "aliases": aliases,
            "origin": "",
            "motivation": [],
            "sectors": [],
            "scope": "GLOBAL",
            "targets_italy": mentions_italy,
            "tools": sorted(g_tools.get(gid, []))[:8],
            "ttps": pick_ttps(g_ttps.get(gid, set()), index),
            "first_seen": "",
            "last_activity": "",
            "confidence": "MEDIUM",
            "summary": shorten(desc, 300),
            "sources": [{"title": f"MITRE ATT&CK {ext_id(g)}", "url": ext_url(g)}] if ext_url(g) else [],
        }
        a.update({k: v for k, v in ov.items() if not k.startswith("_")})
        actors.append(a)
    log(f"MITRE: {len(actors)} attori selezionati su {len(groups)}")
    return actors, index


# ───────────────────────── feed ─────────────────────────


def local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def parse_feed(raw):
    root = ET.fromstring(raw)
    items = []
    for el in root.iter():
        if local(el.tag) not in ("item", "entry"):
            continue
        f = {"title": "", "link": "", "date": None, "desc": ""}
        for ch in el:
            n = local(ch.tag)
            txt = (ch.text or "").strip()
            if n == "title":
                f["title"] = strip_html(txt)
            elif n == "link":
                href = ch.attrib.get("href")
                if href and (ch.attrib.get("rel", "alternate") == "alternate"):
                    f["link"] = href
                elif txt and not f["link"]:
                    f["link"] = txt
            elif n in ("pubDate", "published", "updated", "date") and not f["date"]:
                f["date"] = parse_date(txt)
            elif n in ("description", "summary", "encoded", "content") and not f["desc"]:
                f["desc"] = strip_html(txt)
        if f["title"] and f["link"].lower().startswith(("http://", "https://")) and f["date"]:
            items.append(f)
    return items


def actor_regex(a):
    terms = [a["name"], *a["aliases"], *a.get("match", [])]
    terms = [t for t in terms if len(t) >= 4]
    if not terms:
        return None
    return re.compile(r"(?<!\w)(" + "|".join(re.escape(t) for t in terms) + r")(?!\w)", re.I)


def collect_feeds(feeds, actors, cutoff, ignore_urls, offline, verbose):
    regs = [(a, actor_regex(a)) for a in actors]
    regs = [(a, r) for a, r in regs if r]
    campaigns = {}
    ok = 0
    for feed in feeds:
        if offline and not feed["url"].startswith("file://"):
            continue
        try:
            items = parse_feed(fetch(feed["url"]))
        except Exception as e:
            log(f"feed {feed['name']}: {e}")
            continue
        ok += 1
        kept = 0
        for it in items:
            if it["date"] < cutoff or it["link"] in ignore_urls:
                continue
            text = it["title"] + " " + it["desc"]
            italy = bool(ITALY_RE.search(text))
            hits = [a for a, r in regs if r.search(text)]
            for a in hits:
                d = day(it["date"])
                if d > a.get("last_activity", ""):
                    a["last_activity"] = d
                a.setdefault("_mentions", []).append((it["date"], it["title"], it["link"]))
            make = (hits and (feed.get("scope") == "IT" or italy or feed.get("trusted"))) or feed.get("all_items")
            if not make:
                continue
            cid = "AUTO-" + hashlib.sha1(it["link"].encode()).hexdigest()[:10]
            names = [a["name"] for a in hits]
            summary = shorten(it["desc"], 280)
            if len(names) > 1:
                summary = (summary + " | Citati anche: " + ", ".join(names[1:])).strip(" |")
            campaigns[cid] = {
                "id": cid,
                "title": shorten(it["title"], 140),
                "actor": names[0] if names else "",
                "start": day(it["date"]),
                "end": "",
                "scope": "IT" if (feed.get("scope") == "IT" or italy) else "GLOBAL",
                "sectors": [],
                "vector": "",
                "malware": [],
                "ttps": [],
                "confidence": "LOW",
                "tlp": "CLEAR",
                "summary": summary,
                "sources": [{"title": feed["name"], "url": it["link"]}],
                "auto": True,
            }
            kept += 1
        if verbose:
            log(f"feed {feed['name']}: {len(items)} voci, {kept} campagne")
    log(f"feed letti: {ok}/{len(feeds)}")
    return campaigns


# ───────────────────────── normalizzazione ─────────────────────────


def norm_actor(a):
    out = {
        "id": str(a["id"]),
        "name": str(a["name"]),
        "aliases": as_list(a.get("aliases")),
        "origin": str(a.get("origin", "")),
        "motivation": as_list(a.get("motivation")),
        "sectors": as_list(a.get("sectors")),
        "scope": str(a.get("scope", "GLOBAL")),
        "targets_italy": bool(a.get("targets_italy", False)),
        "tools": as_list(a.get("tools")),
        "ttps": as_list(a.get("ttps")),
        "first_seen": str(a.get("first_seen", "")),
        "last_activity": str(a.get("last_activity", "")),
        "confidence": str(a.get("confidence", "MEDIUM")).upper(),
        "summary": str(a.get("summary", "")),
        "sources": [s for s in a.get("sources", []) if isinstance(s, dict) and s.get("url")],
    }
    if out["targets_italy"] and out["scope"] == "GLOBAL":
        out["scope"] = "IT"
    return out


def norm_campaign(c):
    return {
        "id": str(c["id"]),
        "title": str(c["title"]),
        "actor": str(c.get("actor", "")),
        "start": str(c.get("start", "")),
        "end": str(c.get("end", "")),
        "scope": str(c.get("scope", "GLOBAL")),
        "sectors": as_list(c.get("sectors")),
        "vector": str(c.get("vector", "")),
        "malware": as_list(c.get("malware")),
        "ttps": as_list(c.get("ttps")),
        "confidence": str(c.get("confidence", "LOW")).upper(),
        "tlp": str(c.get("tlp", "CLEAR")).upper(),
        "summary": str(c.get("summary", "")),
        "sources": [s for s in c.get("sources", []) if isinstance(s, dict) and s.get("url")],
        **({"auto": True} if c.get("auto") else {}),
    }


# ───────────────────────── main ─────────────────────────


def main():
    ap = argparse.ArgumentParser(description="Genera cti_db.json per cti.html")
    ap.add_argument("--out", default="cti_db.json")
    ap.add_argument("--curated", default="cti_curated.json")
    ap.add_argument("--cache-dir", default=".cti_cache")
    ap.add_argument("--mitre-url", default=MITRE_URL)
    ap.add_argument("--days", type=int, default=WINDOW_DAYS)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=args.days)

    curated = load_json(args.curated, {}, strict=True)
    overrides = curated.get("actors", {}) if isinstance(curated.get("actors"), dict) else {}
    extra_actors = [a for a in curated.get("extra_actors", []) if isinstance(a, dict) and a.get("id") and a.get("name")]
    cur_campaigns = [c for c in curated.get("campaigns", []) if isinstance(c, dict) and c.get("id") and c.get("title")]
    ignore_urls = set(as_list(curated.get("ignore_urls")))
    feeds = curated.get("feeds") if isinstance(curated.get("feeds"), list) else FEEDS

    prev = load_json(args.out, None)
    if not isinstance(prev, dict) or prev.get("sample") is True:
        prev = None   # i dati di esempio non vanno mai riutilizzati

    # 1) attori e tecniche
    mitre = get_mitre(args)
    index = {}
    if mitre:
        actors, index = actors_from_mitre(mitre, overrides)
    elif prev:
        log("MITRE non disponibile: riuso gli attori dell'ultima esecuzione")
        actors = copy.deepcopy([a for a in prev.get("actors", []) if a.get("id") not in {e["id"] for e in extra_actors}])
        for a in actors:
            a.update({k: v for k, v in overrides.get(a["name"], {}).items() if not k.startswith("_")})
        index = {t["id"]: t for t in prev.get("ttps", []) if t.get("id")}
    else:
        actors = []
    actors += [copy.deepcopy(a) for a in extra_actors]
    if not actors:
        log("nessun attore: impossibile generare il database (non sovrascrivo nulla)")
        return 2
    if prev:  # non perdere date di attivita gia acquisite
        old = {a["id"]: a.get("last_activity", "") for a in prev.get("actors", [])}
        for a in actors:
            if old.get(a["id"], "") > a.get("last_activity", ""):
                a["last_activity"] = old[a["id"]]

    # 2) feed
    auto = collect_feeds(feeds, actors, cutoff, ignore_urls, args.offline, args.verbose)
    if prev:  # conserva le campagne auto ancora in finestra
        for c in prev.get("campaigns", []):
            if c.get("auto") and c.get("id") not in auto and c.get("start", "") >= day(cutoff) \
                    and not any(s.get("url") in ignore_urls for s in c.get("sources", [])):
                auto[c["id"]] = c
    auto_list = sorted(auto.values(), key=lambda c: c.get("start", ""), reverse=True)[:MAX_AUTO_CAMPAIGNS]

    # fonti recenti negli attori
    for a in actors:
        ms = sorted(a.pop("_mentions", []), key=lambda m: m[0], reverse=True)
        seen = {s["url"] for s in a["sources"]}
        for _, title, link in ms:
            if len([s for s in a["sources"] if "attack.mitre.org" not in s["url"]]) >= MAX_ACTOR_SOURCES:
                break
            if link not in seen:
                a["sources"].append({"title": shorten(title, 80), "url": link})
                seen.add(link)

    # 3) assemblaggio
    campaigns = {c["id"]: norm_campaign(c) for c in cur_campaigns}
    for c in auto_list:
        campaigns.setdefault(c["id"], norm_campaign(c))
    camp_list = sorted(campaigns.values(), key=lambda c: c["start"], reverse=True)
    actor_list = sorted((norm_actor(a) for a in actors), key=lambda a: a["name"].lower())

    used = {t for i in (*actor_list, *camp_list) for t in i["ttps"]}
    ttps = []
    for t in sorted(used):
        base = index.get(t) or index.get(t.split(".")[0]) or {}
        ttps.append({
            "id": t,
            "name": base.get("name", ""),
            "tactic": base.get("tactic", ""),
            "url": base.get("url") or "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/",
        })

    db = {
        "schema": 1,
        "sample": False,
        "updated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": args.days,
        "actors": actor_list,
        "campaigns": camp_list,
        "ttps": ttps,
    }
    write_json_atomic(args.out, db)
    log(f"scritto {args.out}: {len(actor_list)} attori, {len(camp_list)} campagne, {len(ttps)} tecniche")
    return 0


if __name__ == "__main__":
    sys.exit(main())
