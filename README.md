# Tyr - Escáner de Vulnerabilidades

![Tyr Banner](https://via.placeholder.com/800x200/000000/FFFFFF?text=Tyr+Security+Scanner)

## 🛡️ ¿Qué es Tyr?

Tyr es un escáner de vulnerabilidades escrito en Python que analiza proyectos de software en busca de dependencias con vulnerabilidades conocidas. Nombrado en honor al dios nórdico de la guerra y la justicia, Tyr busca proteger tus proyectos identificando posibles puntos débiles en las dependencias.

## ⚡ Características Principales

- **🔍 Escaneo Automático**: Detecta automáticamente archivos de dependencias en múltiples lenguajes
- **📊 Base de Datos Actualizada**: Consulta la base de datos oficial de NVD (National Vulnerability Database)
- **🎨 Reportes Detallados**: Genera reportes en formato Markdown con información completa
- **🚀 Rendimiento Optimizado**: Soporte para API key de NVD para escaneos más rápidos
- **🎯 Detección Precisa**: Identifica vulnerabilidades por versión específica
- **🌈 Interfaz Colorida**: Salida en terminal con colores para mejor legibilidad

## 📋 Lenguajes y Gestores Soportados

- **JavaScript/Node.js**: `package.json`
- **PHP**: `composer.json`
- **Python**: `requirements.txt`
- **Ruby**: `Gemfile`
- **Java**: `pom.xml`, `build.gradle`
- **Rust**: `Cargo.toml`
- **Docker**: `Dockerfile`

## 🚀 Instalación

### Prerrequisitos

- Python 3.7 o superior
- pip (gestor de paquetes de Python)

### Instalación de Dependencias

```bash
pip install requests
```

### Descarga del Script

```bash
git clone https://github.com/tu-usuario/tyr.git
cd tyr
```

## 💻 Uso Básico

### Escaneo Simple

```bash
python3 tyr.py /ruta/a/tu/proyecto
```

### Escaneo con Nombre Personalizado

```bash
python3 tyr.py /ruta/a/tu/proyecto -n "Mi Proyecto"
```

### Escaneo Rápido con API Key de NVD

```bash
python3 tyr.py /ruta/a/tu/proyecto -k TU_API_KEY_NVD
```

### Modo Silencioso (Solo Reporte)

```bash
python3 tyr.py /ruta/a/tu/proyecto -q
```

## 🎯 Opciones de Línea de Comandos

| Opción               | Descripción                                             |
| -------------------- | ------------------------------------------------------- |
| `project_path`       | Ruta del proyecto a escanear (obligatorio)              |
| `-n, --project-name` | Nombre del proyecto para el reporte                     |
| `-o, --output`       | Nombre del archivo de salida (default: `tyr_report.md`) |
| `-k, --api-key`      | API Key para NVD (reduce el delay entre requests)       |
| `-q, --quiet`        | Modo silencioso (solo muestra mensaje final)            |
| `-h, --help`         | Mostrar ayuda y salir                                   |
| `-v, --version`      | Mostrar versión y salir                                 |

## 🔑 Obtención de API Key de NVD

Para obtener una API key y acelerar los escaneos:

1. Visita [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Regístrate en el portal
3. Solicita tu API key gratuita
4. Úsala con el parámetro `-k`

**Nota**: Con API key el delay entre requests es de 0.6s, sin API key es de 6s.

## 📊 Ejemplo de Salida

### En Terminal

```
╔══════════════════════════════════════════╗
║                                          ║
║        ████████╗██╗   ██╗██████╗         ║
║        ╚══██╔══╝╚██╗ ██╔╝██╔══██╗        ║
║           ██║    ╚████╔╝ ██████╔╝        ║
║           ██║     ╚██╔╝  ██╔══██╗        ║
║           ██║      ██║   ██║  ██║        ║
║           ╚═╝      ╚═╝   ╚═╝  ╚═╝        ║
║                                          ║
║         Security Scanner v1.0.0          ║
║          by Christian Benitez            ║
║                                          ║
╚══════════════════════════════════════════╝

Tyr - Escáner de Vulnerabilidades v1.0.0
==================================================
🔍 Escaneando proyecto: mi-proyecto
📁 Ruta: /ruta/a/mi-proyecto
📄 Archivos encontrados: 3
📦 Dependencias encontradas: 15

🔍 Buscando vulnerabilidades...
✅ Con API Key: proceso más rápido

🚨 Vulnerabilidades encontradas: 2
📊 Reporte generado: tyr_report.md

📈 Resumen:
  CRITICAL: 1
  HIGH: 1

📋 Detalles de vulnerabilidades:

▶ flask 1.0.1 - CRITICAL (CVSS: 9.8)
  CVE: CVE-2018-1000656
  Tipo: Code Injection
  Descripción: Flask version Before 0.12.3 contains a CWE-94: Improper Control of Generation of Code vulnerability...
  Remediation: Update to a patched version
```

### Reporte Markdown Generado

El script genera un reporte en formato Markdown con tabla de vulnerabilidades y enlaces a los CVEs correspondientes.

## 🛠️ Estructura del Proyecto

```
tyr/
├── tyr.py              # Script principal
├── README.md           # Este archivo
└── tyr_report.md       # Reporte de ejemplo (generado)
```

## 🔧 Desarrollo

### Estructura del Código

- **NVDClient**: Cliente para interactuar con la API de NVD
- **Colors**: Clase para manejo de colores en terminal
- **Funciones de parsing**: Para diferentes tipos de archivos de dependencias
- **Generador de reportes**: Crea reportes en formato Markdown

### Extender Funcionalidad

Para agregar soporte para nuevos gestores de paquetes:

1. Agregar el patrón del archivo en `find_dependency_files()`
2. Implementar el parser en `parse_dependencies()`
3. Probar con proyectos reales

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Haz fork del proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## ⚠️ Limitaciones

- El escaneo depende de la disponibilidad de la API de NVD
- Sin API key, el proceso puede ser lento para proyectos con muchas dependencias
- La detección de versiones vulnerables puede tener falsos positivos/negativos

## 🆘 Soporte

Si encuentras algún problema:

1. Revisa que tengas la última versión
2. Verifica que tu API key de NVD sea válida (si estás usando una)
3. Abre un issue en el repositorio con:
   - Descripción del problema
   - Comando ejecutado
   - Salida del error
   - Sistema operativo y versión de Python

---

**Desarrollado por Christian Benitez** - ¿Preguntas? Abre un issue en el repositorio.
