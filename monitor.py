#!/usr/bin/env python3
"""
Fortinet PSIRT Monitor — via NVD API
Recupere les CVE Fortinet depuis l'API NVD et alerte via webhook Discord.
"""

import os
import json
import re
import requests
from datetime import datetime, timezone, timedelta

# ── Config ────────────────────────────────────────────────────────────────────
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK"]
SEEN_FILE = "seen_cves.json"

# API NVD (gratuite, pas de cle requise pour usage basique)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Produits Fortinet a surveiller
WATCHED_KEYWORDS = [
    "FortiOS", "FortiGate", "FortiManager", "FortiAnalyzer",
    "FortiSwitch", "FortiProxy", "FortiAP", "FortiClient",
    "FortiWeb", "FortiMail", "FortiSIEM"
]

# Severites a notifier (mettre [] pour toutes)
MIN_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",
    "HIGH":     "\U0001f7e0",
    "MEDIUM":   "\U0001f7e1",
    "LOW":      "\U0001f535",
}

SEVERITY_COLOR = {
    "CRITICAL": 0xFF0000,
    "HIGH":     0xFF6600,
    "MEDIUM":   0xFFCC00,
    "LOW":      0x0099FF,
}

# ── Cache ─────────────────────────────────────────────────────────────────────
def load_seen() -> set:
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    return set()

def save_seen(seen: set):
    with open(SEEN_FILE, "w") as f:
        json.dump(sorted(list(seen)), f, indent=2)

# ── NVD API ───────────────────────────────────────────────────────────────────
def fetch_fortinet_cves(days_back: int = 3) -> list:
    """
    Recupere les CVE Fortinet publiees sur les N derniers jours via l'API NVD.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)
    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "keywordSearch": "fortinet",
        "pubStartDate":  pub_start,
        "pubEndDate":    pub_end,
        "resultsPerPage": 100,
    }

    headers = {"User-Agent": "FortinetSecurityMonitor/3.0 (github-actions)"}

    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        print(f"[NVD] {len(vulns)} CVE(s) Fortinet trouvees sur les {days_back} derniers jours.")
        return vulns
    except requests.RequestException as e:
        print(f"[ERREUR] Appel NVD echoue : {e}")
        return []

def parse_severity(cve_item: dict) -> tuple[str, float]:
    """
    Extrait la severite et le score CVSS depuis un item NVD.
    Retourne (severity_label, score).
    """
    metrics = cve_item.get("cve", {}).get("metrics", {})

    # Priorite CVSSv3.1 > v3.0 > v2
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            if key.startswith("cvssMetricV3"):
                severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
            else:
                # CVSSv2 : pas de label severity natif, on le calcule
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            return severity, score

    return "UNKNOWN", 0.0

def is_watched(cve_item: dict) -> bool:
    """
    Verifie si la CVE concerne un produit Fortinet surveille.
    """
    cve = cve_item.get("cve", {})
    # Cherche dans les descriptions
    descriptions = " ".join(
        d.get("value", "") for d in cve.get("descriptions", [])
    )
    # Cherche dans les configurations CPE
    cpe_text = ""
    for node in cve.get("configurations", []):
        for match in node.get("cpeMatch", []):
            cpe_text += match.get("criteria", "") + " "

    full_text = (descriptions + " " + cpe_text).lower()

    if not WATCHED_KEYWORDS:
        return True

    return any(kw.lower() in full_text for kw in WATCHED_KEYWORDS)

# ── Discord ───────────────────────────────────────────────────────────────────
def send_discord(cve_item: dict):
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "N/A")

    # Description en anglais (fallback en)
    descriptions = cve.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "Pas de description disponible."
    )
    desc = desc[:350] + "..." if len(desc) > 350 else desc

    severity, score = parse_severity(cve_item)
    emoji = SEVERITY_EMOJI.get(severity, "\u26aa")
    color = SEVERITY_COLOR.get(severity, 0x808080)

    # Date de publication
    published = cve.get("published", "")[:10]
    modified  = cve.get("lastModified", "")[:10]

    # References
    refs = cve.get("references", [])
    refs_text = "\n".join(
        f"- [{r.get('source', 'ref')}]({r.get('url', '')})"
        for r in refs[:3]
    ) or "Aucune reference."

    # Produits affectes via CPE
    cpe_products = set()
    for node in cve.get("configurations", []):
        for match in node.get("cpeMatch", []):
            cpe = match.get("criteria", "")
            parts = cpe.split(":")
            if len(parts) >= 5:
                product = parts[4].replace("_", " ").title()
                cpe_products.add(product)
    products_text = ", ".join(sorted(cpe_products)[:6]) or "N/A"

    embed = {
        "title": f"{emoji} [{severity}] {cve_id}",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "description": desc,
        "color": color,
        "fields": [
            {"name": "\U0001f4ca Score CVSS",    "value": str(score),     "inline": True},
            {"name": "\U0001f4c5 Publie le",     "value": published,      "inline": True},
            {"name": "\U0001f504 Mis a jour",    "value": modified,       "inline": True},
            {"name": "\U0001f5a5\ufe0f Produits", "value": products_text, "inline": False},
            {"name": "\U0001f517 References",    "value": refs_text,      "inline": False},
        ],
        "footer": {
            "text": f"NVD API • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        },
    }

    payload = {"embeds": [embed]}
    r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
    r.raise_for_status()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    seen = load_seen()
    cves = fetch_fortinet_cves(days_back=3)

    new_count = 0
    skipped   = 0

    for item in cves:
        cve_id = item.get("cve", {}).get("id", "")
        if not cve_id:
            continue

        # Deja notifie
        if cve_id in seen:
            skipped += 1
            continue

        # Filtre produit
        if not is_watched(item):
            print(f"[SKIP] {cve_id} — produit non surveille")
            skipped += 1
            continue

        # Filtre severite
        severity, score = parse_severity(item)
        if MIN_SEVERITIES and severity not in MIN_SEVERITIES:
            print(f"[SKIP] {cve_id} — severite '{severity}' ignoree")
            skipped += 1
            continue

        # Envoi Discord
        try:
            send_discord(item)
            seen.add(cve_id)
            new_count += 1
            print(f"[OK] Notifie : {cve_id} ({severity} — {score})")
        except requests.RequestException as e:
            print(f"[ERREUR] Discord pour {cve_id} : {e}")

    save_seen(seen)

    print(f"\nResume : {new_count} nouvelle(s) CVE notifiee(s), {skipped} ignoree(s).")

    # Message Discord de recap si aucune nouvelle CVE
    if new_count == 0:
        try:
            requests.post(
                DISCORD_WEBHOOK,
                json={"content": f"\u2705 **Scan Fortinet OK** — Aucune nouvelle CVE sur les 3 derniers jours ({len(seen)} CVE suivies au total)"},
                timeout=10,
            )
        except requests.RequestException as e:
            print(f"[ERREUR] Discord recap : {e}")

if __name__ == "__main__":
    main()
