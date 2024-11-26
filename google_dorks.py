import requests
from bs4 import BeautifulSoup

def google_dorks(dork_query, proxies=None):
    url = f"https://www.google.com/search?q={dork_query}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Safari/537.36"
    }

    try:
        print(f"Ejecutando Google Dork: {dork_query}")
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        results = []
        for link in soup.select("a"):
            href = link.get("href")
            if href and "http" in href:
                results.append(href)
        return results[:10]  # Devuelve los primeros 10 resultados
    except requests.exceptions.RequestException as e:
        print(f"Error al ejecutar el Dork: {e}")
        return []
