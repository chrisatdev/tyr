# Tyr - Escáner de Vulnerabilidades y Seguridad

## 🛡️ ¿Qué es Tyr?

Tyr es un escáner de seguridad completo escrito en Python que analiza proyectos de software en busca de:

- **Dependencias con vulnerabilidades** usando las bases de datos NVD, OSV y GitHub Advisory
- **Vulnerabilidades de seguridad** en código fuente (SQL Injection, XSS, Command Injection, etc.)
- **Problemas de calidad de código** (code smells, secrets hardcodeados, etc.)

Nombrado en honor al dios nórdico de la guerra y la justicia, Tyr busca proteger tus proyectos identificando potenciales debilidades de seguridad.

## ⚡ Características Principales

- **🔌 Sistema Dual de Plugins**: Arquitectura extensible como nmap para escáneres de vulnerabilidades Y analizadores de código
- **🔍 Escaneo Multi-Fuente**: Plugins integrados para NVD, OSV y GitHub Security Advisory
- **🛡️ Análisis de Código de Seguridad**: 8 analizadores integrados para detectar vulnerabilidades OWASP Top 10
- **🎯 Analizadores de Código**: Detecta SQLi, XSS, Command Injection, CSRF, Path Traversal, Auth, Secrets, Code Smells
- **📊 Reportes Detallados**: Genera reportes completos en formato Markdown con colores
- **🚀 Rendimiento Optimizado**: Delays configurables y soporte para API keys
- **🌈 Interfaz Colorida**: Salida en terminal con colores para mejor legibilidad
- **🔗 Enlaces CVE**: Enlaces directos a detalles de vulnerabilidades
- **⚙️ Configuración Flexible**: Habilitar/deshabilitar analizadores específicos con argumentos personalizados
- **💰 100% Gratis**: No requiere APIs pagadas - todas las funcionalidades funcionan sin API keys

## 📋 Lenguajes Soportados

### Gestores de Paquetes (Escaneo de Dependencias)

- **JavaScript/Node.js**: `package.json`
- **PHP**: `composer.json`
- **Python**: `requirements.txt`, `pyproject.toml`
- **Ruby**: `Gemfile`
- **Java**: `pom.xml`, `build.gradle`
- **Rust**: `Cargo.toml`
- **Go**: `go.mod`

### Análisis de Código Fuente

- **PHP**: Soporte completo para todos los patrones de seguridad
- **JavaScript/Node.js**: Express, Hono, Next.js, React
- **Python**: Flask, Django
- **Java**: Spring, servlets
- **Ruby**: Rails
- **Go**: Librería estándar

## 🚀 Instalación

### Prerrequisitos

- Python 3.7 o superior (3.11+ para leer lockfiles TOML como `poetry.lock`, `uv.lock` y `Cargo.lock`; en versiones anteriores Tyr usa el manifiesto y avisa)
- pip (gestor de paquetes de Python)

### Instalación de Dependencias

```bash
pip install requests
```

### Inicio Rápido

```bash
git clone https://github.com/chrisatdev/tyr.git
cd tyr
python3 tyr.py --list-plugins
```

## 💻 Uso

### 1. Listar Plugins Disponibles

```bash
python3 tyr.py --list-plugins
```

### 2. Escaneo de Vulnerabilidades de Dependencias

```bash
# Usar plugins específicos de vulnerabilidades
python3 tyr.py /ruta/proyecto --plugins nvd

# Usar múltiples plugins
python3 tyr.py /ruta/proyecto --plugins nvd,osv

# Usar todos los escáneres de vulnerabilidades
python3 tyr.py /ruta/proyecto --plugins all
```

### 3. Análisis de Seguridad de Código (NUEVO!)

```bash
# Usar analizadores de código específicos
python3 tyr.py /ruta/proyecto --analyzers sql-injection,xss-detector

# Usar todos los analizadores de seguridad (recomendado)
python3 tyr.py /ruta/proyecto --analyzers all

# Usar analizador específico con argumentos personalizados
python3 tyr.py /ruta/proyecto --analyzers sql-injection --strict-mode true
```

### 4. Escaneo Combinado (Vulnerabilidades + Código)

```bash
# Escaneo completo de seguridad
python3 tyr.py /ruta/proyecto --plugins nvd,osv --analyzers all

# Escaneo OWASP Top 10
python3 tyr.py /ruta/proyecto --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal
```

### 5. Con API Keys (Más Rápido)

**Recomendado: guardar las keys en un archivo privado y limitarlas a una sola ejecución.**
Evita `export` en los archivos de inicio del shell (todo proceso que se lance
hereda la key) y evita `-k` / `--github-token` (el valor queda en el historial
del shell y es visible en `ps`).

Para obtener las keys, consulta [Obtención de API Keys](#-obtención-de-api-keys):
[API Key de NVD](#api-key-de-nvd-opcional) y
[token de GitHub](#token-de-github-requerido-por-github-advisory).

```bash
# Configuración única: pide la key sin mostrarla y la guarda con permisos 600
(umask 077; mkdir -p ~/.config/tyr && chmod 700 ~/.config/tyr \
  && read -rsp "NVD API key: " k && echo \
  && printf '%s' "$k" > ~/.config/tyr/nvd.key && chmod 600 ~/.config/tyr/nvd.key; unset k)

# En cada ejecución: la key solo existe en el entorno de este comando
NVD_API_KEY="$(<~/.config/tyr/nvd.key)" python3 tyr.py /ruta/proyecto --plugins osv,nvd
```

#### Token de GitHub para `github-advisory`

El plugin `github-advisory` **no** lee el repositorio analizado. Busca cada
dependencia (nombre de paquete + ecosistema) en la base **pública** de Security
Advisories de GitHub mediante la API GraphQL, que rechaza peticiones sin
autenticar. Por eso necesita un token de **GitHub** (uno de GitLab no funciona),
pero ese token no requiere acceso a ninguno de tus repositorios.

Primero crea el token como se indica en
[Token de GitHub](#token-de-github-requerido-por-github-advisory), y luego:

```bash
# Configuración única
(umask 077; mkdir -p ~/.config/tyr && chmod 700 ~/.config/tyr \
  && read -rsp "GitHub token: " t && echo \
  && printf '%s' "$t" > ~/.config/tyr/github.token && chmod 600 ~/.config/tyr/github.token; unset t)

# Verifica que el token puede consultar la base de advisories (devuelve un totalCount)
curl -s -X POST https://api.github.com/graphql \
  -H "Authorization: Bearer $(<~/.config/tyr/github.token)" \
  -d '{"query":"{ securityVulnerabilities(first:1, ecosystem:NPM, package:\"lodash\") { totalCount } }"}'

# Ejecuta con ambas keys limitadas a este comando
NVD_API_KEY="$(<~/.config/tyr/nvd.key)" \
GITHUB_TOKEN="$(<~/.config/tyr/github.token)" \
  python3 tyr.py /ruta/proyecto --plugins osv,nvd,github-advisory
```

OSV ya importa los GitHub Security Advisories (IDs GHSA), por lo que
`--plugins osv` cubre la mayor parte de los mismos datos sin token.

En GitLab CI, define `NVD_API_KEY` como variable de CI/CD **masked** y
**protected** en lugar de commitearla o pasarla por línea de comandos.

```bash
# No recomendado: se filtra por historial del shell, ps y entornos heredados
python3 tyr.py /ruta/proyecto --plugins nvd -k TU_API_KEY_NVD
export NVD_API_KEY="tu_key_aqui"
```

### 6. Nombre de Proyecto y Salida Personalizados

```bash
python3 tyr.py /ruta/proyecto --plugins nvd,osv --analyzers all -n "Mi Proyecto" -o mi_reporte.md
```

## 🎯 Opciones de Línea de Comandos

| Opción | Descripción |
|--------|-------------|
| `project_path` | Ruta del proyecto a escanear (requerido) |
| `--list-plugins` | Listar todos los plugins disponibles y salir |
| `-p, --plugins` | Plugins de vulnerabilidades: nvd, osv, github-advisory, all |
| `-a, --analyzers` | Analizadores de código o 'all' |
| `-n, --project-name` | Nombre del proyecto para el reporte |
| `-o, --output` | Archivo de salida (default: `tyr_report.md`) |
| `-k, --nvd-api-key` | API key de NVD para escaneos más rápidos ([cómo obtenerla](#api-key-de-nvd-opcional); preferir la variable `NVD_API_KEY`, ver [Con API Keys](#5-con-api-keys-más-rápido)) |
| `--github-token` | Token de GitHub para plugin GitHub Advisory ([cómo obtenerlo](#token-de-github-requerido-por-github-advisory); preferir la variable `GITHUB_TOKEN`) |
| `-d, --delay` | Delay entre requests (default: 1.0) |
| `-q, --quiet` | Modo silencioso |
| `--verbose` | Salida verbosa |
| `-h, --help` | Mostrar ayuda |
| `-v, --version` | Mostrar versión |

## 🛡️ Plugins de Seguridad Disponibles

### Escáneres de Vulnerabilidades (Análisis de Dependencias)

| Plugin | Descripción | API Key |
|--------|-------------|---------|
| `nvd` | National Vulnerability Database (Gobierno US) | Opcional ([obtener key](#api-key-de-nvd-opcional)) |
| `osv` | Open Source Vulnerabilities (Google) | No requerida |
| `github-advisory` | GitHub Security Advisory Database | Requerido ([token classic, sin scopes](#token-de-github-requerido-por-github-advisory)) |

### Analizadores de Código (Análisis de Código Fuente)

| Analizador | Descripción | Lenguajes |
|------------|-------------|-----------|
| `sql-injection` | Detecta vulnerabilidades de inyección SQL | PHP, JS, Python, Java |
| `xss-detector` | Detecta XSS (Cross-Site Scripting) | PHP, JS, React, Vue, Python |
| `auth-checker` | Detecta falta de autenticación/autorización | Express, PHP, Flask, Django |
| `command-injection` | Detecta riesgos de inyección de comandos | PHP, JS, Python, Java, Ruby |
| `csrf-protection` | Detecta falta de protección CSRF | HTML, Express, Flask, Django |
| `path-traversal` | Detecta vulnerabilidades de path traversal | PHP, JS, Python, Java, Go |
| `secrets-scanner` | Detecta secrets hardcodeados, API keys, tokens | Todos los lenguajes |
| `code-smell` | Detecta problemas de calidad de código | Todos los lenguajes |

### Argumentos de los Analizadores

Cada analizador soporta argumentos personalizados:

```bash
# SQL Injection con modo estricto
python3 tyr.py /ruta --analyzers sql-injection --strict-mode true

# XSS solo patrones React
python3 tyr.py /ruta --analyzers xss-detector --check-react true --check-dom false

# Auth checker con endpoints críticos personalizados
python3 tyr.py /ruta --analyzers auth-checker --critical-endpoints "delete,admin,payment"

# Secrets scanner con detección de entropía
python3 tyr.py /ruta --analyzers secrets-scanner --min-entropy 4.5 --check-entropy true

# Code smell detector
python3 tyr.py /ruta --analyzers code-smell --max-function-lines 30 --max-parameters 3
```

## 📊 Cobertura OWASP Top 10

Tyr cubre los riesgos de seguridad más críticos:

| Categoría OWASP | Analizador(es) |
|-----------------|----------------|
| A01:2021 - Broken Access Control | path-traversal, csrf-protection, auth-checker |
| A02:2021 - Cryptographic Failures | secrets-scanner, auth-checker |
| A03:2021 - Injection | sql-injection, xss-detector, command-injection |
| A05:2021 - Security Misconfiguration | secrets-scanner |
| A07:2021 - Authentication Failures | auth-checker, secrets-scanner |

## 💰 Comparación: Gratis vs Herramientas Pagadas

| Característica | Tyr | SonarQube | Snyk | Veracode |
|----------------|-----|-----------|------|----------|
| Detección SQL Injection | ✅ | ✅ | ✅ | ✅ |
| Detección XSS | ✅ | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ | ✅ |
| Protección CSRF | ✅ | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ✅ | ✅ | ✅ |
| Revisión Auth | ✅ | ✅ | ✅ | ✅ |
| Detección Secrets | ✅ | ✅ | ✅ | ✅ |
| **Costo Mensual** | **$0** | **$150+** | **$99+** | **$2000+** |
| Sin Necesidad de API Keys | ✅ | ❌ | ❌ | ❌ |
| Análisis Local | ✅ | Parcial | ❌ | ❌ |

**Ahorro Anual: $1,188 - $24,000+**

## 🔑 Obtención de API Keys

### API Key de NVD (Opcional)

Obtén escaneos más rápidos (0.6s de delay vs 6s sin API key):

1. Visita [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Regístrate y solicita tu API key gratuita
3. Guárdala y úsala como se indica en [Con API Keys](#5-con-api-keys-más-rápido)

### Token de GitHub (requerido por `github-advisory`)

La API GraphQL de GitHub rechaza peticiones sin autenticar, por lo que el
plugin `github-advisory` necesita un token. Crea uno de mínimo privilegio:

1. Ve a <https://github.com/settings/tokens/new>
2. Tipo: **Personal access token (classic)**
3. Scopes: **no marques ningún scope** (solo datos públicos)
4. Expiración: corta (p. ej. 30–90 días)
5. Guárdalo, verifícalo y úsalo como se indica en
   [Token de GitHub para `github-advisory`](#token-de-github-para-github-advisory)

Un token sin scopes puede leer datos públicos como la base de advisories, pero
no puede acceder a tus repositorios, organizaciones ni a la configuración de tu
cuenta.

## 📊 Ejemplo de Salida

```
╔══════════════════════════════════════════╗
║        ████████╗██╗   ██╗██████╗         ║
║        ╚══██╔══╝╚██╗ ██╔╝██╔══██╗        ║
║           ██║    ╚████╔╝ ██████╔╝        ║
║           ██║     ╚██╔╝  ██╔══██╗        ║
║           ██║      ██║   ██║  ██║        ║
║           ╚═╝      ╚═╝   ╚═╝  ╚═╝        ║
║                                          ║
║         Security Scanner v1.3.0          ║
║          by Christian Benitez            ║
║                                          ║
╚══════════════════════════════════════════╝

Tyr - Security Scanner v1.3.0
==================================================
🔍 Escaneando proyecto: mi-proyecto
📁 Ruta: /ruta/a/mi-proyecto

📦 Escaneo de Dependencias:
   • Archivos de paquetes: 3 (package.json, requirements.txt, composer.json)
   • Total de dependencias: 25

🔍 Análisis de Código:
   • Analizadores: sql-injection, xss-detector, auth-checker, command-injection, csrf-protection, path-traversal, secrets-scanner

🔍 Buscando vulnerabilidades...
📡 Usando fuentes: NVD, OSV, GitHub Advisory
✅ Con API Key de NVD: escaneo más rápido

📊 Resultados:
   Vulnerabilidades encontradas: 3
   Problemas de código encontrados: 12

📈 Resumen:
   CRITICAL: 2
   HIGH: 5
   MEDIUM: 6
   LOW: 2

📊 Reporte generado: tyr_report.md
```

## 🛠️ Estructura del Proyecto

```
tyr/
├── tyr.py                      # Script principal del escáner
├── plugins/                    # Directorio de plugins
│   ├── base.py                 # Clase base VulnerabilityPlugin
│   ├── base_analyzer.py        # Clase base AnalyzerPlugin
│   ├── nvd.py                  # Plugin NVD
│   ├── osv.py                  # Plugin OSV
│   ├── github_advisory.py      # Plugin GitHub Advisory
│   ├── sql_injection_detector.py
│   ├── xss_detector.py
│   ├── auth_checker.py
│   ├── command_injection_detector.py
│   ├── csrf_protection_checker.py
│   ├── path_traversal_detector.py
│   ├── secrets_scanner.py
│   ├── code_smell_detector.py
│   └── README.md              # Guía de desarrollo de plugins
├── es/                        # Documentación en español
│   └── README.md
├── README.md                  # Esta documentación
└── tyr_report.md             # Reporte de ejemplo generado
```

## 🔧 Creando Plugins Personalizados

### Plugin de Vulnerabilidades (para escaneo de dependencias)

```python
from plugins.base import VulnerabilityPlugin

class MiPlugin(VulnerabilityPlugin):
    @property
    def name(self) -> str:
        return "mi-plugin"
    
    @property
    def display_name(self) -> str:
        return "Mi Plugin Personalizado"
    
    def is_available(self) -> bool:
        return True
    
    def query_vulnerabilities(self, package_name, package_version, package_type):
        # Implementa la búsqueda de vulnerabilidades
        return []
```

### Plugin Analizador (para escaneo de código fuente)

```python
from plugins.base_analyzer import AnalyzerPlugin

class MiAnalizador(AnalyzerPlugin):
    @property
    def name(self) -> str:
        return "mi-analizador"
    
    @property
    def supported_extensions(self) -> List[str]:
        return ['.js', '.ts']
    
    def analyze_file(self, file_path: Path) -> List[Dict]:
        # Implementa el análisis de código
        return []
```

Consulta [`plugins/README.md`](plugins/README.md) para una guía completa.

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

## 🤝 Contribuciones

Las contribuciones son bienvenidas:

1. Haz fork del proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## ⚠️ Limitaciones

- El escaneo de vulnerabilidades depende de la disponibilidad de las APIs de NVD/OSV/GitHub
- Sin API key de NVD, el escaneo puede ser lento para proyectos grandes
- El análisis de código usa pattern matching - puede tener falsos positivos/negativos

## 🆘 Soporte

Si encuentras algún problema:

1. Verifica que tienes la última versión
2. Confirma que tus API keys son válidas (si usas)
3. Abre un issue con descripción del problema, comando ejecutado, salida del error, SO y versión de Python

---

**Desarrollado por Christian Benitez** - ¿Preguntas? Abre un issue en el repositorio.

**Versión:** 1.3.0  
**Fecha:** 2026-03-06
