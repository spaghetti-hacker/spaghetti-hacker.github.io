#!/usr/bin/env python3
"""Scarica un feed RSS di SecurityWeek scelto a caso e salva gli ultimi articoli in news_sw.json.

Uso:  python3 update_news.py
Poi:  git add news_sw.json && git commit -m "news" && git push

- Ad ogni esecuzione sceglie un feed a caso da FEEDS.
- Se quel feed fallisce (o è vuoto) prova gli altri, sempre in ordine casuale.
- Se falliscono tutti, news_sw.json NON viene toccato (restano le news vecchie).
"""
import json
import random
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

# ── aggiungi qui i feed: "name" è l'etichetta mostrata nella home ──
FEEDS = [
    {"name": "GENERAL", "url": "https://feeds.feedburner.com/securityweek"},
    {"name": "VULNERABILITIES", "url": "https://www.securityweek.com/category/vulnerabilities/feed/"},
    {"name": "ICS-OT", "url": "https://www.securityweek.com/category/ics-ot/feed/"},
]

OUT_FILE = Path(__file__).with_name("news_sw.json")
MAX_ITEMS = 10


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (spaghetti-hacker news updater)"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()


def iso_date(raw: str | None) -> str:
    """'Thu, 29 Oct 2026 09:12:00 +0000' -> '2026-10-29' (stringa vuota se non parsabile)."""
    if not raw:
        return ""
    try:
        return parsedate_to_datetime(raw).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return ""


def read_items(url: str) -> list[dict]:
    root = ET.fromstring(fetch(url))
    items = []
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        if not title or not link.startswith("https://"):
            continue
        items.append({"title": title, "link": link, "date": iso_date(it.findtext("pubDate"))})
        if len(items) >= MAX_ITEMS:
            break
    return items


def main() -> int:
    order = FEEDS[:]
    random.shuffle(order)

    for feed in order:
        try:
            items = read_items(feed["url"])
        except Exception as e:
            print(f"[{feed['name']}] errore: {e}", file=sys.stderr)
            continue
        if not items:
            print(f"[{feed['name']}] nessun articolo valido", file=sys.stderr)
            continue

        data = {
            "source": feed["name"],
            "updated": datetime.now().strftime("%Y-%m-%d"),
            "items": items,
        }
        OUT_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"[{feed['name']}] salvati {len(items)} articoli in {OUT_FILE.name}")
        return 0

    print("nessun feed disponibile: file non modificato", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
