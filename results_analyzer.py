import re

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
        'vulnerabilities': [],
        'interesting_folders': []
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
        
        # Analizar vulnerabilidades detectadas (filtrar solo las vulnerabilidades)
        vulnerability_matches = re.findall(r'\|_\s*[^\n]+', scan_output)
        for vuln in vulnerability_matches:
            # Agregar solo vulnerabilidades reales
            if "Potentially interesting folder" not in vuln:
                analysis['vulnerabilities'].append(vuln.strip())
        
        # Analizar directorios interesantes (solo los primeros 10)
        folder_matches = re.findall(r"\|   (/[\w\-]+)/:", scan_output)
        for i, folder in enumerate(folder_matches):
            if i < 10:
                analysis['interesting_folders'].append(folder)
            else:
                break

        return analysis

    except Exception as e:
        return {'error': f'Error al analizar los resultados: {str(e)}'}
    
