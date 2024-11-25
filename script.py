import os
import requests
import time
from bs4 import BeautifulSoup
import re
import json
import subprocess

# Menú principal
def main_menu():
    print("=== Herramienta de Automatización ===")
    print("1. Ejecutar Google Dorks")
    print("2. Escanear con Nmap")
    print("3. Salir")
    choice = input("Seleccione una opción: ")
    return choice

# Función para Google Dorks
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

# Función para ejecutar Nmap
def nmap_scan(host, scan_type="default"):
    """
    Escanea un host utilizando Nmap.

    :param host: Dominio o IP a escanear.
    :param scan_type: Tipo de escaneo (default, vuln, ssl).
    :return: Resultado del escaneo en formato dict.
    """
    try:
        if scan_type == "default":
            print(f"Ejecutando escaneo básico para: {host}")
            command = ["nmap", host]
        elif scan_type == "vuln":
            print(f"Ejecutando escaneo de vulnerabilidades para: {host}")
            command = ["nmap", host, "--script", "vuln"]
        elif scan_type == "ssl":
            print(f"Ejecutando escaneo SSL para: {host}")
            command = ["nmap", host, "--script", "ssl-enum-ciphers"]
        else:
            print(f"Tipo de escaneo no reconocido: {scan_type}")
            return {}
        
        # Ejecutar el comando nmap
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"Error al ejecutar Nmap: {result.stderr}")
            return {}

    except Exception as e:
        print(f"Error al ejecutar Nmap: {e}")
        return {}

def analyze_nmap_results(scan_output):
    """
    Analiza los resultados del escaneo Nmap y extrae información relevante.
    
    :param scan_output: Resultado del escaneo Nmap (stdout).
    :return: Diccionario con los resultados del análisis.
    """
    analysis = {
        'host': None,
        'status': None,
        'rDNS': None,
        'ports': [],
        'filtered_ports': 'None',
        'vulnerabilities': []
    }

    # Verificar si el resultado contiene información
    if not scan_output:
        return {'error': 'No se encontraron resultados de escaneo'}

    # Extraer información del escaneo
    try:
        # Analizar el host
        host_match = re.search(r'Nmap scan report for (\S+)', scan_output)
        if host_match:
            analysis['host'] = host_match.group(1)

        # Analizar el estado del host (up/down)
        status_match = re.search(r'Host is (\w+)', scan_output)
        if status_match:
            analysis['status'] = status_match.group(1).capitalize()

        # Analizar el rDNS (si existe)
        rDNS_match = re.search(r'rDNS record for (\S+)', scan_output)
        if rDNS_match:
            analysis['rDNS'] = rDNS_match.group(1)
        
        # Analizar puertos y servicios
        port_matches = re.findall(r'(\d+/tcp)\s+(\w+)\s+(\w+)', scan_output)
        for port_match in port_matches:
            port = port_match[0]
            state = port_match[1]
            service = port_match[2]
            analysis['ports'].append({
                'port': port,
                'status': state,
                'service': service
            })
        
        # Analizar puertos filtrados (si existe información)
        filtered_match = re.search(r'Not shown: (\d+) filtered tcp ports', scan_output)
        if filtered_match:
            analysis['filtered_ports'] = filtered_match.group(1)
        
        # Analizar vulnerabilidades detectadas
        vulnerability_matches = re.findall(r'\|_?[^\n]+', scan_output)
        for vuln in vulnerability_matches:
            analysis['vulnerabilities'].append(vuln.strip())

        return analysis

    except Exception as e:
        return {'error': f'Error al analizar los resultados: {str(e)}'}

# Script principal
if __name__ == "__main__":
    while True:
        choice = main_menu()
        if choice == "1":
            query = input("Ingrese el Dork para buscar: ")
            proxies = None
            # Agregar soporte para proxies si es necesario
            use_proxies = input("¿Usar proxies? (s/n): ").lower()
            if use_proxies == "s":
                proxies = {"http": "http://proxy_ip:port", "https": "http://proxy_ip:port"}
            results = google_dorks(query, proxies)
            print("\nResultados:")
            for idx, result in enumerate(results, 1):
                print(f"{idx}. {result}")
            time.sleep(5)  # Espera para evitar bloqueos

        elif choice == "2":
            host_input = input("Ingrese un host o lista de hosts (separados por comas): ")
            hosts = host_input.split(",")
            scan_type = input("Seleccione el tipo de escaneo (default, vuln, ssl): ").lower()
            for host in hosts:
                result = nmap_scan(host.strip(), scan_type)
                print(f"\nResultados para {host}:")
                analysis = analyze_nmap_results(result)
                print(json.dumps(analysis, indent=4))

        elif choice == "3":
            print("Saliendo del programa. ¡Adiós!")
            break
        else:
            print("Opción no válida. Intente nuevamente.")
