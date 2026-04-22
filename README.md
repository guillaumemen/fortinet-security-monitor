# 🛡️ Fortinet Security Monitor — Google Gemini Edition

Bot de veille cybersécurité **100% gratuit** basé sur **Google Gemini 2.5 Flash**
avec **Google Search Grounding** (résultats en temps réel).

## ✅ Pourquoi Gemini ?
- **Gratuit** — 1500 requêtes/jour, pas de carte bancaire
- **Google Search intégré** — résultats en temps réel
- **Gemini 2.5 Flash** — modèle rapide et intelligent

# ⚙️ Configuration (2 secrets GitHub)


## 🕐 Planning
- **8h00 CEST** (6h UTC)
- **13h00 CEST** (11h UTC)

## 📋 Modifier les termes surveillés
Dans `monitor.py`, liste `watch_terms` :
```python
"watch_terms": [
    "FortiGate exploit CVE 2025",
    "FortiOS zero-day attack",
    # Ajoute tes termes ici
],
```

## 💬 Alertes Discord
- 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW
- ✅ Scan OK si aucune alerte
