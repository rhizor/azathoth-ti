# Azathoth TI - Guía de Instalación

## Requisitos del Sistema

### Requisitos Mínimos
- Python 3.10+
- pip
- Git

### Requisitos Recomendados
- Python 3.11+
- 4GB RAM
- Conexión a internet (para APIs de threat intelligence)

## Instalación

### Método 1: Entorno Virtual (Recomendado)

```bash
# Clonar repositorio
git clone https://github.com/rhizor/azathoth-ti.git
cd azathoth-ti

# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
# Linux/macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python3 -m src --help
```

### Método 2: Instalación Global

```bash
git clone https://github.com/rhizor/azathoth-ti.git
cd azathoth-ti
pip install -r requirements.txt
```

## Configuración de API Keys

### Variables de Entorno

```bash
# AlienVault OTX (recomendado)
export ALIENVAULT_API_KEY="tu_api_key"

# AbuseIPDB (opcional)
export ABUSEIPDB_API_KEY="tu_api_key"

# Agregar al ~/.bashrc para persistencia
echo 'export ALIENVAULT_API_KEY="tu_key"' >> ~/.bashrc
source ~/.bashrc
```

### Obtener API Keys

- **AlienVault OTX**: https://otx.alienvault.com/api
- **AbuseIPDB**: https://www.abuseipdb.com/account/api

## Verificación de Instalación

```bash
# Ver ayuda
python3 -m src --help

# Ver estadísticas (base de datos vacía)
python3 -m src stats
```

## Estructura de Archivos

```
~/.azathoth/
└── data/
    └── azathoth.db    # Base de datos SQLite
```

## Solución de Problemas

### Error: "No module named 'src'"

```bash
# Asegúrate de estar en el directorio correcto
cd azathoth-ti

# O instala globalmente
pip install -e .
```

### Error de permisos

```bash
# Usa --user si no tienes permisos de admin
pip install -r requirements.txt --user
```

### Error de sintaxis (Python 3.8)

```bash
# Actualiza a Python 3.10+
python3 --version

# O usa python3.10 si está disponible
python3.10 -m src --help
```

## Actualización

```bash
# Pull latest changes
git pull origin master

# Reinstalar dependencias si es necesario
pip install -r requirements.txt
```

## Desinstalación

```bash
# Desactivar entorno virtual
deactivate

# Eliminar carpeta
rm -rf azathoth-ti

# O si fue instalado globalmente
pip uninstall -r requirements.txt
```
