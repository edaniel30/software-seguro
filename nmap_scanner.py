import subprocess

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
