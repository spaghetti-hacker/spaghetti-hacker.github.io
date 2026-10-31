#!/usr/bin/env python3
"""Scarica da NVD le CVE pubblicate negli ultimi WINDOW_DAYS giorni con CVSS >= MIN_SCORE
e le salva in cve_db.json (letto da cve.html). Marca come KEV quelle presenti nel catalogo CISA.

Uso:   python3 update_cve.py
Cron:  una volta al giorno basta (es. 15 9 * * *)

- Chiave NVD opzionale: export NVD_API_KEY=...  (senza chiave rallenta da solo per rispettare il rate limit)
- Se NVD non risponde, cve_db.json NON viene toccato.
- Se il catalogo KEV non risponde, il file viene scritto lo stesso con "kev_checked": false.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

WINDOW_DAYS = 7
MIN_SCORE = 8.0
PAGE_SIZE = 2000
DESC_MAX = 400

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_FILE = Path("/home/re/Desktop/SpaghettiHacker/spaghetti-hacker.github.io/cve_db.json")

API_KEY = os.environ.get("NVD_API_KEY", "").strip()
# senza chiave ~5 richieste / 30 s; con chiave ~50 / 30 s
PAUSE = 0.8 if API_KEY else 6.5
RETRY_WAIT = 35
MAX_RETRIES = 4

METRIC_KEYS = [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]


def get_json(url: str) -> dict:
    headers = {"User-Agent": "Mozilla/5.0 (spaghetti-hacker cve updater)"}
    if API_KEY and url.startswith(NVD_URL):
        headers["apiKey"] = API_KEY
    last = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 503) and attempt < MAX_RETRIES:
                print(f"  HTTP {e.code}, attendo {RETRY_WAIT}s (tentativo {attempt}/{MAX_RETRIES})", file=sys.stderr)
                time.sleep(RETRY_WAIT)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
            if attempt < MAX_RETRIES:
                time.sleep(5)
                continue
            raise
    raise last  # non dovrebbe arrivare qui


def best_score(metrics: dict):
    """Punteggio massimo tra le versioni CVSS presenti (preferendo le valutazioni 'Primary').
    Ritorna (score, versione) oppure (None, None)."""
    best = (None, None)
    for key, ver in METRIC_KEYS:
        entries = metrics.get(key) or []
        primary = [e for e in entries if e.get("type") == "Primary"] or entries
        for e in primary:
            s = (e.get("cvssData") or {}).get("baseScore")
            if isinstance(s, (int, float)) and (best[0] is None or s > best[0]):
                best = (float(s), ver)
    return best


def severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def fetch_cves(start: datetime, end: datetime) -> list[dict]:
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")
    items, index, total = [], 0, None
    while total is None or index < total:
        q = urllib.parse.urlencode({
            "pubStartDate": fmt(start), "pubEndDate": fmt(end),
            "resultsPerPage": PAGE_SIZE, "startIndex": index,
        })
        data = get_json(f"{NVD_URL}?{q}")
        total = int(data.get("totalResults", 0))
        vulns = data.get("vulnerabilities") or []
        print(f"  NVD: {index + len(vulns)}/{total}")
        if not vulns:
            break
        for v in vulns:
            cve = v.get("cve") or {}
            score, ver = best_score(cve.get("metrics") or {})
            if score is None or score < MIN_SCORE:
                continue
            desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
            desc = " ".join(desc.split())
            if len(desc) > DESC_MAX:
                desc = desc[:DESC_MAX].rstrip() + "…"
            published = cve.get("published", "")
            items.append({
                "id": cve.get("id", ""),
                "published": published + "Z" if published and not published.endswith("Z") else published,
                "score": score,
                "cvss": ver,
                "severity": severity(score),
                "desc": desc,
            })
        index += len(vulns)
        if index < total:
            time.sleep(PAUSE)
    if total == 0:
        raise RuntimeError("NVD ha restituito 0 risultati: probabile problema, non sovrascrivo")
    return items


def load_kev() -> set[str] | None:
    try:
        data = get_json(KEV_URL)
        return {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}
    except Exception as e:
        print(f"  KEV non disponibile: {e}", file=sys.stderr)
        return None


def main() -> int:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=WINDOW_DAYS)
    print(f"CVE pubblicate {start:%Y-%m-%d %H:%M} -> {end:%Y-%m-%d %H:%M} UTC, CVSS >= {MIN_SCORE}")

    try:
        items = fetch_cves(start, end)
    except Exception as e:
        print(f"errore NVD: {e}", file=sys.stderr)
        return 1

    kev = load_kev()
    for it in items:
        it["kev"] = bool(kev and it["id"] in kev)
    items = [i for i in items if i["id"]]
    items.sort(key=lambda i: i["published"], reverse=True)

    out = {
        "updated": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": WINDOW_DAYS,
        "min_score": MIN_SCORE,
        "kev_checked": kev is not None,
        "items": items,
    }
    tmp = OUT_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    tmp.replace(OUT_FILE)
    print(f"salvate {len(items)} CVE in {OUT_FILE.name}" + ("" if kev is not None else " (senza flag KEV)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
