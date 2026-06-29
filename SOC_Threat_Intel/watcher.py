import os
import json
import subprocess
from datetime import datetime, timedelta, timezone

# Rutas
DIRECTORIO_ACTUAL = os.path.dirname(os.path.abspath(__file__))
RUTA_REPO_LOCAL = os.path.join(DIRECTORIO_ACTUAL, "cvelistV5")
ARCHIVO_ACTIVOS = os.path.join(DIRECTORIO_ACTUAL, "activos_cves.txt")
ARCHIVO_SALIDA = os.path.join(DIRECTORIO_ACTUAL, "lista_cves.txt")
DIAS_BUSQUEDA = 2  

print("=== THREAT INTELLIGENCE WATCHER ===")
print("1. Búsqueda Global (Descargar TODOS los CVEs)")
print("2. Búsqueda por Activos (Filtrar solo tecnologías en activos_cves.txt)")
print("-" * 50)

while True:
    modo = input("[?] Selecciona el modo de operación (1 o 2): ").strip()
    if modo in ["1", "2"]:
        break
    print("[!] Opción inválida. Escribe 1 o 2.")

print(f"\n[*] Sincronizando repositorio local en: {RUTA_REPO}...")
try:
    subprocess.run(["git", "-C", RUTA_REPO, "pull", "origin", "main"], 
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[+] Sincronización completada.")
except subprocess.CalledProcessError:
    print("[!] Advertencia: Falló el 'git pull'. Se usarán los datos locales actuales.")
except FileNotFoundError:
    print("[!] Error: Git no encontrado o ruta incorrecta.")
    exit()

delta_path = os.path.join(RUTA_REPO, "deltaLog.json")
if not os.path.exists(delta_path):
    print(f"[!] Error: No se encontró 'deltaLog.json' en {RUTA_REPO}")
    exit()

print(f"[*] Escaneando bitácora de cambios (deltaLog.json)...")
try:
    with open(delta_path, "r", encoding="utf-8") as f:
        delta_data = json.load(f)
except json.JSONDecodeError:
    print("[!] Error al leer deltaLog.json. Archivo corrupto.")
    exit()

limite_fecha = datetime.now(timezone.utc) - timedelta(days=DIAS_BUSQUEDA)
cves_modificados = set()

for bloque in delta_data:
    try:
        fetch_time = datetime.fromisoformat(bloque.get("fetchTime", "").replace("Z", "+00:00"))
        if fetch_time < limite_fecha:
            break 
            
        for cve in bloque.get("new", []) + bloque.get("updated", []):
            if "cveId" in cve:
                cves_modificados.add(cve["cveId"])
    except ValueError:
        continue

if not cves_modificados:
    print(f"[-] No hubo actividad de CVEs en las últimas {DIAS_BUSQUEDA*24} horas.")
    exit()

print(f"[*] Se detectaron {len(cves_modificados)} CVEs con actividad reciente.")

cves_finales = set()

if modo == "1":
    print("[*] Modo Global activado. Extrayendo todos los registros...")
    cves_finales = cves_modificados
    
elif modo == "2":
    if not os.path.exists(ARCHIVO_ACTIVOS):
        print(f"\n[!] Error: Para usar el Modo 2 debes crear el archivo '{ARCHIVO_ACTIVOS}'")
        exit()
        
    with open(ARCHIVO_ACTIVOS, "r") as f:
        tecnologias = [linea.strip().lower() for linea in f if linea.strip()]
        
    if not tecnologias:
        print(f"\n[!] Error: El archivo '{ARCHIVO_ACTIVOS}' está vacío.")
        exit()
        
    print(f"[*] Modo Activos activado. Buscando {len(tecnologias)} tecnologías específicas en los archivos JSON...")
    
    for cve_id in cves_modificados:
        partes = cve_id.split("-")
        if len(partes) != 3: continue
        
        anio, secuencia = partes[1], partes[2]
        carpeta_xxx = secuencia[:-3] + "xxx" if len(secuencia) >= 4 else "0xxx"
        ruta_cve_json = os.path.join(RUTA_REPO, "cves", anio, carpeta_xxx, f"{cve_id}.json")
        
        if not os.path.exists(ruta_cve_json): continue
            
        try:
            with open(ruta_cve_json, "r", encoding="utf-8") as f:
                contenido_crudo = f.read().lower()
                for tech in tecnologias:
                    if tech in contenido_crudo:
                        cves_finales.add(cve_id)
                        break 
        except Exception:
            pass

if cves_finales:
    print(f"\n[+] Extracción completada: {len(cves_finales)} CVEs listos para procesar.")
    
    cves_existentes = set()
    if os.path.exists(ARCHIVO_SALIDA):
        with open(ARCHIVO_SALIDA, "r") as f:
            cves_existentes = set(linea.strip().upper() for linea in f if linea.strip())
            
    cves_nuevos_reales = cves_finales - cves_existentes
    
    if cves_nuevos_reales:
        with open(ARCHIVO_SALIDA, "a") as f:
            for cve in cves_nuevos_reales:
                f.write(f"{cve}\n")
        print(f"[+] Se agregaron {len(cves_nuevos_reales)} CVEs nuevos a '{ARCHIVO_SALIDA}'.")
        print("[>] Ahora puedes ejecutar tu generador de Dashboard.")
    else:
        print("[-] Todos los CVEs extraídos ya estaban en tu lista maestra.")
else:
    print(f"\n[-] No se encontraron amenazas que coincidan con tus criterios.")