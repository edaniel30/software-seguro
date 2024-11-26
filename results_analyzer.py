import re

def analyze_nmap_results(scan_output):
    """
    Analiza los resultados del escaneo Nmap y extrae información relevante.
    
    :param scan_output: Resultado del escaneo Nmap (stdout).
    :return: Diccionario con los resultados del análisis.
    """
    # Convertir a cadena si no lo es
    if not isinstance(scan_output, str):
        scan_output = str(scan_output)  # Convertimos explícitamente a cadena
    
    # Limpiar la cadena
    scan_output = scan_output.strip()
    if not scan_output:
        return {'error': 'El contenido del escaneo está vacío'}

    analysis = {
        'host': None,
        'status': None,
        'rDNS': None,
        'ports': [],
        'filtered_ports': None,
        'vulnerabilities': [],
        'ssl': None
    }

    try:
        # Analizar el host
        host_match = re.search(r'Nmap scan report for (\S+)', scan_output)
        if host_match:
            analysis['host'] = host_match.group(1)

        # Analizar el estado del host (up/down)
        status_match = re.search(r'Host is (\w+)', scan_output)
        if status_match:
            analysis['status'] = status_match.group(1).capitalize()

        # Analizar el rDNS
        rDNS_match = re.search(r'rDNS record for (\S+)', scan_output)
        if rDNS_match:
            analysis['rDNS'] = rDNS_match.group(1)

        # Analizar puertos y servicios
        port_matches = re.findall(r'(\d+/tcp)\s+(\w+)\s+(\w+)', scan_output)
        for port_match in port_matches:
            port, state, service = port_match
            analysis['ports'].append({'port': port, 'status': state, 'service': service})

        # Analizar puertos filtrados
        filtered_match = re.search(r'Not shown: (\d+) filtered tcp ports', scan_output)
        if filtered_match:
            analysis['filtered_ports'] = int(filtered_match.group(1))

        # Analizar SSL
        ssl_section = re.search(r'\| ssl-enum-ciphers:(.*?)\|_\s+least strength:', scan_output, re.DOTALL)
        if ssl_section:
            ssl_data = ssl_section.group(1).strip()
            analysis['ssl'] = parse_ssl_section(ssl_data)

        return analysis

    except Exception as e:
        return {'error': f'Error al analizar los resultados: {str(e)}'}

def parse_ssl_section(ssl_data):
    """
    Procesa y estructura la sección SSL en un formato JSON legible.
    
    :param ssl_data: Texto crudo de la sección SSL.
    :return: Diccionario con la información estructurada.
    """
    ssl_info = {
        'tls_versions': {},
    }
    
    # Verificar si ssl_data no está vacío
    if not ssl_data or not isinstance(ssl_data, str):
        print("SSL Data vacío o no válido")
        return ssl_info

    # Separar por TLS versiones
    tls_versions = re.findall(r'\|\s+TLSv([\d\.]+):\s*\n(.*?)(?=\|\s+TLSv[\d\.]+:|$)', ssl_data, re.DOTALL)
    if not tls_versions:
        print("No se encontraron versiones TLS")
    else:
        for version, details in tls_versions:
            ciphers = re.findall(r'(\S+) \(', details)  # Extraer nombres de los cifrados
            ssl_info['tls_versions'][version] = {'ciphers': ciphers}

    return ssl_info
