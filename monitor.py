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

    payload = {"embeds": [{
        "title":  f"{emoji}  Alerte Sécurité — {sev.upper()}",
        "color":  color,
        "fields": [
            {"name": "🔎 Terme surveillé", "value": f"`{term}`",                "inline": True},
            {"name": "⚡ Sévérité",        "value": f"{emoji} {sev.upper()}",   "inline": True},
            {"name": "📋 Résumé",          "value": data.get("summary", "N/A"), "inline": False},
            {"name": "🔗 Sources",         "value": sources,                    "inline": False},
        ],
        "footer":    {"text": "Security Monitor • Google Gemini + Search Grounding"},
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }]}

    try:
        r = requests.post(CONFIG["webhook_url"], json=payload, timeout=10)
        r.raise_for_status()
        logger.info(f"  ✅ Discord [{sev.upper()}] : {term}")
    except requests.RequestException as e:
        logger.error(f"  ❌ Webhook Discord : {e}")

def send_discord_ok(total):
    now = datetime.datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")
    payload = {"embeds": [{
        "title":       "✅ Scan terminé — Aucune alerte",
        "color":       0x2ECC71,
        "description": f"**{total}** terme(s) analysé(s) — **0** alerte(s)\n_{now}_",
        "footer":      {"text": "Security Monitor • Google Gemini + Search Grounding"},
        "timestamp":   datetime.datetime.utcnow().isoformat(),
    }]}
    try:
        requests.post(CONFIG["webhook_url"], json=payload, timeout=10)
    except requests.RequestException:
        pass

# ── BOUCLE PRINCIPALE ─────────────────────────────────────────────────────────
def run():
    if not CONFIG["api_key"]:
        logger.error("❌ GEMINI_API_KEY manquante.")
        return
    if not CONFIG["webhook_url"]:
        logger.error("❌ WEBHOOK_URL manquante.")
        return

    cache   = load_cache(CONFIG["seen_cache"])
    alerted = 0
    terms   = CONFIG["watch_terms"]

    logger.info(f"🚀 Démarrage — {len(terms)} terme(s) avec Gemini + Google Search")

    for term in terms:
        logger.info(f"🔍 {term}")
        result = query_gemini(term)

        if not result:
            time.sleep(2)
            continue
        if not result.get("found") or result.get("severity") == "none":
            logger.info("  ↳ Rien de notable")
            time.sleep(2)
            continue

        aid = alert_id(term, result.get("summary", ""))
        if not is_fresh(cache, aid):
            logger.info("  ↳ Déjà alerté (cache 20h)")
            time.sleep(2)
            continue

        send_discord(term, result)
        cache[aid] = datetime.datetime.utcnow().isoformat()
        alerted += 1
        time.sleep(4)   # Respecte le rate limit Gemini free (15 RPM)

    if alerted == 0:
        send_discord_ok(len(terms))

    save_cache(CONFIG["seen_cache"], cache)
    logger.info(f"✔ Terminé — {alerted}/{len(terms)} alerte(s) envoyée(s)")

if __name__ == "__main__":
    run()
