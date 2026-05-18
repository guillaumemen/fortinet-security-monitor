#!/usr/bin/env python3
"""
Perplexity Security Monitor Bot — version Google Gemini (GRATUIT)
Surveille des termes de sécurité via Gemini 2.5 Flash + Google Search Grounding
et alerte via webhook Discord.
"""

import os, json, time, logging, hashlib, datetime, re, requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("security-monitor")

CONFIG = {
    "api_key":      os.getenv("GEMINI_API_KEY", ""),
    "webhook_url":  os.getenv("WEBHOOK_URL", ""),
    "model":        "gemini-2.5-flash-preview-04-17",   # modèle gratuit avec grounding
    "seen_cache":   "seen_alerts.json",
    "watch_terms": [
        "FortiGate exploit CVE",
        "FortiClient vulnerability critical",
        "FortiOS zero-day attack",
        "Fortinet security patch urgent",
        "FortiGate breach IOC",
        "FortiSwitch RCE vulnerability",
        "SSL-VPN Fortinet compromise",
        "FortiGate privilege escalation admin",
        "FortiGate LDAP authentication bypass",
        "ANSSI Fortinet vulnérabilité critique",
        
    ],
    "system_prompt": (
        "Tu es un expert en cybersécurité réseau. "
        "Réponds UNIQUEMENT en JSON strict, sans aucun texte ou markdown autour. "
        "Format attendu exactement : "
        '{ "found": true ou false, '
        '"severity": "critical" ou "high" ou "medium" ou "low" ou "none", '
        '"summary": "résumé court en français en 2 phrases maximum", '
        '"sources": ["url1", "url2"] }'
    ),
}

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "none": "⚪"}
SEVERITY_COLOR = {"critical": 0xFF0000, "high": 0xFF8C00, "medium": 0xFFD700, "low": 0x4169E1}

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "{model}:generateContent?key={key}"
)

# ── CACHE ─────────────────────────────────────────────────────────────────────
def load_cache(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_cache(path, cache):
    with open(path, "w") as f:
        json.dump(cache, f, indent=2)

def alert_id(term, summary):
    return hashlib.md5(f"{term}:{summary[:80]}".encode()).hexdigest()

def is_fresh(cache, aid, ttl_hours=20):
    if aid not in cache:
        return True
    ts = datetime.datetime.fromisoformat(cache[aid])
    return (datetime.datetime.utcnow() - ts).total_seconds() > ttl_hours * 3600

# ── API GEMINI + GOOGLE SEARCH GROUNDING ──────────────────────────────────────
def query_gemini(term):
    url = GEMINI_URL.format(model=CONFIG["model"], key=CONFIG["api_key"])
    payload = {
        "system_instruction": {
            "parts": [{"text": CONFIG["system_prompt"]}]
        },
        "contents": [{
            "parts": [{"text": (
                f'Recherche les actualités des dernières 48h sur : "{term}". '
                "Y a-t-il de nouvelles vulnérabilités, CVE critiques, exploits actifs ou IOC publiés ? "
                "Utilise Google Search pour vérifier. "
                "Réponds UNIQUEMENT en JSON valide, sans markdown ni texte autour."
            )}]
        }],
        "tools": [{"google_search": {}}],   # Google Search Grounding activé
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 512,
        },
    }

    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()

        # Extraction du texte de la réponse
        raw = data["candidates"][0]["content"]["parts"][0]["text"].strip()

        # Nettoyage si Gemini wrape quand même dans des backticks
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        # Extraction des sources depuis groundingMetadata si disponibles
        sources = []
        grounding = data["candidates"][0].get("groundingMetadata", {})
        for chunk in grounding.get("groundingChunks", []):
            uri = chunk.get("web", {}).get("uri", "")
            if uri:
                sources.append(uri)

        result = json.loads(raw)
        # Merge des sources depuis le grounding si le modèle n'en a pas fourni
        if not result.get("sources") and sources:
            result["sources"] = sources[:3]

        return result

    except requests.RequestException as e:
        logger.error(f"Erreur API Gemini pour '{term}': {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"  Réponse: {e.response.text[:300]}")
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Parsing impossible pour '{term}': {e}")
    return None

# ── DISCORD WEBHOOK ───────────────────────────────────────────────────────────
def send_discord(term, data):
    sev    = data.get("severity", "none")
    emoji  = SEVERITY_EMOJI.get(sev, "⚪")
    color  = SEVERITY_COLOR.get(sev, 0x808080)
    sources = "\n".join(data.get("sources", [])[:3]) or "Aucune source disponible"
import requests
import json
import os
import re
from bs4 import BeautifulSoup
from datetime import datetime, timezone

# ── Config ───────────────────────────────────────────────────────────────────
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK"]
SEEN_FILE       = "seen_cves.json"
PSIRT_URL       = "https://www.fortiguard.com/psirt"

# Produits à surveiller (laisser vide [] pour tous les produits)
WATCHED_PRODUCTS = ["FortiOS", "FortiManager", "FortiAnalyzer", "FortiGate",
                    "FortiSwitch", "FortiProxy", "FortiAP"]

# Sévérités à notifier (mettre [] pour toutes)
MIN_SEVERITIES = ["Critical", "High", "Medium", "Low"]

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
}

# ── Helpers ──────────────────────────────────────────────────────────────────
def load_seen() -> set:
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    return set()

def save_seen(seen: set):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)

def fetch_psirt_advisories() -> list[dict]:
    """Scrape the FortiGuard PSIRT page and return a list of advisories."""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; FortinetSecurityMonitor/2.0)"}
    advisories = []
    page = 1

    while True:
        params = {"page": page}
        resp = requests.get(PSIRT_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # Each advisory is inside a <tr> or a block — adapt selector to real DOM
        rows = soup.select("table tbody tr") or soup.select(".advisory-row")

        if not rows:
            # Fallback: parse raw text blocks from the page
            break

        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 4:
                continue

            fg_id    = cells[0].get_text(strip=True)  # FG-IR-XX-XXX
            cve_text = cells[0].get_text()
            cve_ids  = re.findall(r"CVE-\d{4}-\d+", cve_text)
            products = [p.get_text(strip=True) for p in cells[2].find_all("a")] if len(cells) > 2 else []
            date_str = cells[3].get_text(strip=True) if len(cells) > 3 else ""
            severity = cells[-1].get_text(strip=True).lower() if cells else "unknown"
            title    = cells[1].get_text(strip=True) if len(cells) > 1 else ""

            advisories.append({
                "fg_id":    fg_id,
                "cve_ids":  cve_ids,
                "title":    title,
                "products": products,
                "date":     date_str,
                "severity": severity,
                "url":      f"https://www.fortiguard.com/psirt/{fg_id}",
            })

        # Check if there's a "Next" page
        next_btn = soup.select_one("a[aria-label='Next']") or soup.find("a", string=re.compile(r"Next", re.I))
        if not next_btn:
            break
        page += 1
        if page > 3:  # Limite à 3 pages (~45 CVE max par run)
            break

    return advisories

def is_watched(advisory: dict) -> bool:
    """Return True if the advisory concerns a watched product (or all if list empty)."""
    if not WATCHED_PRODUCTS:
        return True
    for product in advisory["products"]:
        for watched in WATCHED_PRODUCTS:
            if watched.lower() in product.lower():
                return True
    return False

def send_discord(advisory: dict):
    emoji = SEVERITY_EMOJI.get(advisory["severity"], "⚪")
    severity_label = advisory["severity"].upper()
    cve_list = ", ".join(advisory["cve_ids"]) if advisory["cve_ids"] else "N/A"
    products = ", ".join(advisory["products"][:5]) or "N/A"

    embed = {
        "title":       f"{emoji} [{severity_label}] {advisory['title']}",
        "url":         advisory["url"],
        "color":       {"critical": 0xFF0000, "high": 0xFF6600,
                        "medium": 0xFFCC00, "low": 0x0099FF}.get(advisory["severity"], 0x999999),
        "fields": [
            {"name": "🆔 PSIRT ID",   "value": advisory["fg_id"],  "inline": True},
            {"name": "📋 CVE",        "value": cve_list,            "inline": True},
            {"name": "📅 Publié le",  "value": advisory["date"],    "inline": True},
            {"name": "🖥️ Produits",  "value": products,            "inline": False},
        ],
        "footer": {"text": f"FortiGuard PSIRT • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"},
    }
    payload = {"embeds": [embed]}
    r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
    r.raise_for_status()

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    seen = load_seen()
    advisories = fetch_psirt_advisories()
    new_count = 0

    for adv in advisories:
        key = adv["fg_id"]
        if key in seen:
            continue
        if not is_watched(adv):
            continue
        if MIN_SEVERITIES and adv["severity"].capitalize() not in MIN_SEVERITIES:
            continue

        send_discord(adv)
        seen.add(key)
        new_count += 1
        print(f"✅ Notifié : {key} ({adv['severity']}) — {', '.join(adv['cve_ids'])}")

    save_seen(seen)

    if new_count == 0:
        # Envoie un message "tout va bien" uniquement si aucune nouvelle CVE
        requests.post(DISCORD_WEBHOOK, json={
            "content": f"✅ **Scan PSIRT OK** — Aucune nouvelle CVE détectée ({len(seen)} CVE suivis)"
        }, timeout=10)
        print("✅ Aucune nouvelle CVE.")

if __name__ == "__main__":
    main()
