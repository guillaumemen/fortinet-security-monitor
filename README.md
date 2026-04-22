# 🛡️ Fortinet Security Monitor

Bot de veille cybersécurité automatique basé sur **Perplexity Sonar Pro**.
Surveille les CVE, exploits et IOC Fortinet — alertes dans Discord via GitHub Actions.

## ⚙️ Configuration (à faire une seule fois)

### 1. Ajouter les secrets GitHub
Settings → Secrets and variables → Actions → **New repository secret**

| Nom du secret          | Valeur                                      |
|------------------------|---------------------------------------------|
| `PERPLEXITY_API_KEY`   | Ta clé API Perplexity (`pplx-...`)          |
| `DISCORD_WEBHOOK_URL`  | L'URL de ton webhook Discord                |

### 2. C'est tout !
Le bot tourne automatiquement **à 8h et 13h CEST** tous les jours.
Tu peux aussi le lancer manuellement : **Actions → Run workflow**.

## 📋 Termes surveillés

Modifie la liste `watch_terms` dans `monitor.py` :

```python
"watch_terms": [
    "FortiGate exploit CVE 2025",
    "FortiClient vulnerability critical",
    "FortiOS zero-day attack",
    "Fortinet security patch urgent",
    "FortiGate breach IOC",
    "FortiSwitch RCE vulnerability",
    "SSL-VPN Fortinet compromise",
    # Ajoute tes termes ici ↓
],
```

## 💬 Alertes Discord

- 🔴 **CRITICAL** — Exploit actif / CVE critique
- 🟠 **HIGH** — Vulnérabilité sévère
- 🟡 **MEDIUM** — Patch recommandé
- 🔵 **LOW** — Info de sécurité
- ✅ **Scan OK** — Aucune alerte détectée

## 🕐 Planification (cron UTC)

| Heure CEST | Heure UTC | Cron expression |
|------------|-----------|-----------------|
| 08:00      | 06:00     | `0 6 * * *`     |
| 13:00      | 11:00     | `0 11 * * *`    |
