# download_nvd.py
import requests
import json
import time

# Exemple : récupérer les CVE via l'API publique NVD (exemple simple)
# Attention : l'API peut limiter le nombre d'appels. Ici on récupère les 2000 dernières.
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000"

resp = requests.get(url)
resp.raise_for_status()
data = resp.json()

with open("cve_data.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print("Fichier cve_data.json créé (nombre d'items):", len(data.get("vulnerabilities", [])))
