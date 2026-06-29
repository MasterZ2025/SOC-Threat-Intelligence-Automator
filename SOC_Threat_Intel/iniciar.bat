@echo off
title SOC Threat Intelligence Automator
echo === Verificando librerias... ===
pip install -r requirements.txt -q

if not exist .env (
    echo [!] ALERTA: No se encontro el archivo .env
    echo Por favor, renombra .env.example a .env y coloca tu token.
    pause
    exit
)

echo.
echo === INICIANDO WATCHER ===
python watcher.py

echo.
echo === INICIANDO ACTUALIZADOR MAESTRO ===
python CVEs.py

echo.
echo [OK] Proceso finalizado. Puedes abrir tu bitacora en Excel.
pause