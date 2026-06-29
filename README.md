# 🛡️ SOC Threat Intelligence Automator

Pipeline de automatización diseñado para Centros de Operaciones de Seguridad (SOC). Este sistema centraliza el monitoreo de vulnerabilidades mediante la sincronización autónoma del repositorio oficial cvelistV5 y el enriquecimiento de datos a través de la API de VulnCheck.

La herramienta implementa una arquitectura de descubrimiento híbrido (Global o por Tecnologías Específicas) que permite la identificación proactiva de amenazas en cuestión de milisegundos. Mediante un flujo de trabajo de Upsert (Inserción/Actualización), el sistema garantiza que la bitácora operativa en Excel contenga siempre la información más reciente, incluyendo el mapeo de mitigaciones según el framework MITRE, análisis de explotabilidad activa y la generación automatizada de Dashboards ejecutivos.

Características principales:

- Sincronización autónoma: Actualización local vía git pull contra el repositorio oficial de CVEs.
- Inteligencia selectiva: Capacidad de filtrado por activos críticos o monitoreo global masivo.
- Enriquecimiento avanzado: Traducción automática de descripciones, mapeo de mitigaciones técnicas y priorización de riesgo.
- Dashboard dinámico: Generación automática de reportes visuales (Severidad, Vectores y Top de Fabricantes) listos para el análisis operativo.

---

## 📋 Requisitos Previos

Antes de comenzar, asegúrate de tener instalados los siguientes componentes en tu estación de trabajo y que estén agregados al `PATH` de tus variables de entorno:

* **[Python 3.8+](https://www.python.org/downloads/)**
* **[Git](https://git-scm.com/downloads)**

---

## 🚀 Guía de Instalación y Configuración

Sigue estos pasos en orden para desplegar el entorno.

### 1. Clonar el repositorio oficial de CVEs
Para garantizar la máxima velocidad y operar de manera local con la información más precisa (evitando retrasos de la NVD), la herramienta requiere la base de datos oficial.

Abre tu terminal, navega hasta la carpeta raíz de este proyecto y ejecuta:
```bash
git clone https://github.com/CVEProject/cvelistV5.git
```

(Nota: Este repositorio pesa varios GBs, por lo que la primera clonación puede tomar unos minutos dependiendo de tu red. Una vez descargado, el script solo actualizará los cambios incrementales).

### 2. Instalación de Dependencias
Instala las librerías de Python necesarias para la ejecución. En tu terminal, ejecuta:

```bash
pip install -r requirements.txt
```

### 3. Configuración de Credenciales (.env)
La herramienta utiliza la API de VulnCheck como respaldo para enriquecer métricas CVSS.

1. Localiza el archivo .env.example en la carpeta.
2. Renómbralo a .env (asegúrate de que no tenga ninguna extensión adicional como .txt).
3. Ábrelo con tu editor preferido y coloca tu token:

```bash
Fragmento de código
VULNCHECK_TOKEN=tu_token_aqui
```
Para obtener tu token de Vulncheck, lo puedes hacerlo desde el [sitio oficial](https://docs.vulncheck.com/api/v3)

### 4. Definir Activos Monitoreados
Abre el archivo activos_cves.txt y escribe las tecnologías clave que deseas que el Watcher vigile cuando uses el "Modo Activos". Escribe una tecnología por línea en minúsculas.
```bash
Ejemplo:

Plaintext
windows
linux
splunk
fortinet
chrome
```

---

## ⚙️ Uso de la Herramienta
Puedes ejecutar el ciclo completo de dos maneras:

### En Windows
### Opción A: Modo Automático
1. Haz doble clic en el archivo iniciar.bat. Este ejecutable:
2. Validará las dependencias instaladas y tu configuración .env.
3. Sincronizará la base de datos local usando git pull de forma silenciosa.
4. Lanzará el Watcher Inteligente (te pedirá elegir entre Búsqueda Global o Búsqueda por Activos).
5. Ejecutará el Script Principal para hacer el enriquecimiento (Upsert) y dibujar el Dashboard en Excel.

### Opción B: Ejecución Manual por Terminal
Si necesitas depurar o correr los módulos por separado:

- Buscar y encolar amenazas:

```bash
python watcher.py
```
- Procesar cola, actualizar datos y generar bitácora:

```bash
python CVEs.py
```

### En Linux
### Opción A: Modo Automático
1. Dale permisos de ejecución al lanzador:
```bash
chmod +x iniciar.sh
```
2. Ejecútalo desde la terminal:
```bash
./iniciar.sh
```

### Opción B: Ejecución Manual
Si prefieres correr los módulos por separado:

- Buscar y encolar amenazas:

```bash
python3 watcher_inteligente.py
```
- Procesar, enriquecer y generar bitácora:

```bash
python3 script_principal.py
```

---

## 📂 Arquitectura del Proyecto
- **watcher.py**: Analiza el deltaLog.json del repositorio Git local para filtrar amenazas nuevas o modificadas en las últimas 48 horas.

- **CVEs.py**: Motor central. Cruza los datos locales con la API, traduce descripciones, integra mitigaciones híbridas (MITRE/CWE), formatea celdas y genera las métricas gráficas.

- **activos_cves.txt**: Diccionario de tecnologías objetivo del equipo.

- **lista_cves.txt**: Archivo puente. El Watcher deposita aquí los identificadores y el script principal los consume (y purga la cola al terminar).

- **cvelistV5/**: Directorio contenedor de la base de datos oficial.

- **bitacora_vulnerabilidades.xlsx**: Entregable final generado dinámicamente.
