# Detección de vulnerabilidades 

Este script es una herramienta de automatización diseñada con fines educativos, que permite realizar dos tareas principales:

1. **Ejecutar Google Dorks**: Realiza búsquedas avanzadas en Google utilizando consultas Dork específicas para encontrar resultados relacionados con vulnerabilidades o información sensible expuesta en Internet.
2. **Escanear con Nmap**: Realiza escaneos de red en un host (dominio o IP) para obtener información sobre puertos abiertos, servicios disponibles, posibles vulnerabilidades y otros detalles sobre la configuración de seguridad de una máquina.

## Requisitos

Para ejecutar este script, debes tener instalados los siguientes requisitos en tu máquina:

### 1. **Python 3.x**
El script está escrito en Python 3. Puedes instalarlo desde el sitio oficial de Python:
- [Python 3.x](https://www.python.org/)

### 2. **Nmap**
El script utiliza la herramienta de escaneo de redes `nmap`, que debe estar instalada en tu máquina. Puedes instalarla en sistemas basados en Debian/Ubuntu con el siguiente comando:

```bash
sudo apt-get install nmap
