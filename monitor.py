#!/usr/bin/env python3
"""
Perplexity Security Monitor Bot
Surveille des termes de sécurité via l'API Sonar et alerte via webhook Discord.
"""

import os, json, time, logging, hashlib, datetime, requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("perplexity-monitor")

CONFIG = {
    "api_key":      os.getenv("PERPLEXITY_API_KEY", ""),
    "webhook_url":  os.getenv("WEBHOOK_URL", ""),
    "model":        "sonar-pro",
    "seen_cache":   "seen_alerts.json",
    "watch_terms": [
        "FortiGate exploit CVE 2025",
        "FortiClient vulnerability critical",
        "FortiOS zero-day attack",
        "Fortinet security patch urgent",
        "FortiGate breach IOC",
        "FortiSwitch RCE vulnerability",
        "SSL-VPN Fortinet compromise",
    ],
    "system_prompt": (
        "Tu es un expert en cybersécurité. "
        "Réponds uniquement en JSON strict, sans aucun texte autour. "
        'Format attendu : { "found": true/false, "severity": "critical|high|medium|low|none", '
        '"summary": "résumé en 2 phrases max en français", "sources": ["url1", "url2"] }'
    ),
}

SEVERITY_EMOJI  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "none": "⚪"}
SEVERITY_COLOR  = {"critical": 0xFF0000, "high": 0xFF8C00, "medium": 0xFFD700, "low": 0x4169E1}
SONAR_URL       = "https://api.perplexity.ai/chat/completions"

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
    """Retourne True si l'alerte n'a PAS encore été envoyée dans les dernières ttl_hours."""
    if aid not in cache:
        return True
    ts = datetime.datetime.fromisoformat(cache[aid])
    return (datetime.datetime.utcnow() - ts).total_seconds() > ttl_hours * 3600

# ── API PERPLEXITY SONAR ──────────────────────────────────────────────────────
def query_perplexity(term):
    headers = {"Authorization": f"Bearer {CONFIG['api_key']}", "Content-Type": "application/json"}
    payload = {
        "model": CONFIG["model"],
        "messages": [
            {"role": "system", "content": CONFIG["system_prompt"]},
            {"role": "user", "content": (
                f'Recherche des actualités récentes (dernières 48h) sur : "{term}". '
                "Y a-t-il des nouvelles vulnérabilités, exploits, CVE critiques ou IOC publiés ? "
                "Réponds UNIQUEMENT en JSON valide, sans markdown."
            )},
        ],
        "temperature": 0.1,
        "search_recency_filter": "day",
        "return_citations": True,
    }
    try:
        r = requests.post(SONAR_URL, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        return json.loads(raw)
    except requests.RequestException as e:
        logger.error(f"Erreur API pour '{term}': {e}")
    except json.JSONDecodeError as e:
        logger.warning(f"JSON invalide pour '{term}': {e}")
    return None

# ── DISCORD WEBHOOK ───────────────────────────────────────────────────────────
def send_discord(term, data):
    sev    = data.get("severity", "none")
    emoji  = SEVERITY_EMOJI.get(sev, "⚪")
    color  = SEVERITY_COLOR.get(sev, 0x808080)
    sources = "\n".join(data.get("sources", [])[:3]) or "Aucune source disponible"

    payload = {"embeds": [{
        "title":  f"{emoji}  Alerte Sécurité — {sev.upper()}",
        "color":  color,
        "fields": [
            {"name": "🔎 Terme surveillé", "value": f"`{term}`",                      "inline": True},
            {"name": "⚡ Sévérité",        "value": f"{emoji} {sev.upper()}",          "inline": True},
            {"name": "📋 Résumé",          "value": data.get("summary", "N/A"),        "inline": False},
            {"name": "🔗 Sources",         "value": sources,                           "inline": False},
        ],
        "footer": {"text": "Perplexity Security Monitor • Sonar Pro"},
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }]}

    try:
        r = requests.post(CONFIG["webhook_url"], json=payload, timeout=10)
        r.raise_for_status()
        logger.info(f"  ✅ Alerte Discord envoyée [{sev.upper()}] : {term}")
    except requests.RequestException as e:
        logger.error(f"  ❌ Erreur webhook Discord : {e}")

def send_discord_summary(alerted_count, total_terms):
    """Envoie un résumé si aucune alerte n'a été trouvée."""
    now = datetime.datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")
    payload = {"embeds": [{
        "title":  "✅ Scan terminé — Aucune alerte",
        "color":  0x2ECC71,
        "description": f"**{total_terms}** terme(s) analysé(s) — **0** alerte(s) détectée(s)\n_{now}_",
        "footer": {"text": "Perplexity Security Monitor • Sonar Pro"},
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }]}
    try:
        requests.post(CONFIG["webhook_url"], json=payload, timeout=10)
    except requests.RequestException:
        pass

# ── BOUCLE PRINCIPALE ─────────────────────────────────────────────────────────
def run():
    if not CONFIG["api_key"]:
        logger.error("❌ PERPLEXITY_API_KEY manquante.")
        return
    if not CONFIG["webhook_url"]:
        logger.error("❌ WEBHOOK_URL manquante.")
        return

    cache   = load_cache(CONFIG["seen_cache"])
    alerted = 0
    terms   = CONFIG["watch_terms"]

    logger.info(f"🚀 Démarrage — {len(terms)} terme(s) à vérifier")

    for term in terms:
        logger.info(f"🔍 {term}")
        result = query_perplexity(term)

        if not result:
            continue
        if not result.get("found") or result.get("severity") == "none":
            logger.info("  ↳ Rien de notable")
            continue

        aid = alert_id(term, result.get("summary", ""))
        if not is_fresh(cache, aid):
            logger.info("  ↳ Déjà alerté (cache 20h)")
            continue

        send_discord(term, result)
        cache[aid] = datetime.datetime.utcnow().isoformat()
        alerted += 1
        time.sleep(1)

    if alerted == 0:
        send_discord_summary(0, len(terms))

    save_cache(CONFIG["seen_cache"], cache)
    logger.info(f"✔ Terminé — {alerted}/{len(terms)} alerte(s) envoyée(s)")

if __name__ == "__main__":
    run()
