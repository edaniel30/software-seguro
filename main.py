import time
import json
from nmap_scanner import nmap_scan
from google_dorks import google_dorks 
from results_analyzer import analyze_nmap_results, analyze_ssl_scan

# Menú principal
def main_menu():
    print("=== Herramienta de Automatización ===")
    print("1. Ejecutar Google Dorks")
    print("2. Escanear con Nmap")
    print("3. Salir")
    choice = input("Seleccione una opción: ")
    return choice

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
                
                # Verifica si se encontró un error o si el análisis fue exitoso
                if 'error' in analysis:
                    print(analysis['error'])
                else:
                    print(json.dumps(analysis, indent=4))

        elif choice == "3":
            print("Saliendo del programa. ¡Adiós!")
            break
        else:
            print("Opción no válida. Intente nuevamente.")
