# Plugins de Tyr

Este directorio contiene los plugins del escáner de seguridad Tyr. Tyr soporta dos tipos de plugins:

1. **Plugins de Vulnerabilidades** - Consultan bases de datos de vulnerabilidades para CVEs conocidas en dependencias
2. **Plugins Analizadores** - Analizan código fuente para problemas de seguridad y calidad

## Plugins Disponibles

### Plugins de Escaneo de Vulnerabilidades

| Plugin | Nombre | Descripción | API Key |
|--------|--------|-------------|---------|
| `nvd.py` | nvd | National Vulnerability Database (Gobierno US) | Opcional |
| `osv.py` | osv | Open Source Vulnerabilities (Google) | No |
| `github_advisory.py` | github-advisory | GitHub Security Advisory Database | Opcional |

### Plugins de Análisis de Código

| Plugin | Nombre | Descripción | Lenguajes |
|--------|--------|-------------|-----------|
| `sql_injection_detector.py` | sql-injection | Detecta inyección SQL | PHP, JS, Python, Java |
| `xss_detector.py` | xss-detector | Detecta XSS (Cross-Site Scripting) | PHP, JS, React, Vue, Python |
| `auth_checker.py` | auth-checker | Detecta falta de autenticación/autorización | Express, PHP, Flask, Django |
| `command_injection_detector.py` | command-injection | Detecta riesgos de inyección de comandos | PHP, JS, Python, Java, Ruby |
| `csrf_protection_checker.py` | csrf-protection | Detecta falta de protección CSRF | HTML, Express, Flask, Django |
| `path_traversal_detector.py` | path-traversal | Detecta vulnerabilidades path traversal | PHP, JS, Python, Java, Go |
| `secrets_scanner.py` | secrets-scanner | Detecta secrets hardcodeados, API keys | Todos |
| `code_smell_detector.py` | code-smell | Detecta problemas de calidad de código | Todos |

## Uso

### Listar Todos los Plugins Disponibles

```bash
python tyr.py --list-plugins
```

### Usar Plugins de Vulnerabilidades

Usar un plugin:
```bash
python tyr.py /ruta/proyecto --plugins nvd
```

Usar múltiples plugins:
```bash
python tyr.py /ruta/proyecto --plugins nvd,osv
```

Usar todos los plugins:
```bash
python tyr.py /ruta/proyecto --plugins all
```

### Usar Analizadores de Código

Usar analizadores específicos:
```bash
python tyr.py /ruta/proyecto --analyzers sql-injection,xss-detector
```

Usar todos los analizadores:
```bash
python tyr.py /ruta/proyecto --analyzers all
```

### Escaneo Combinado

```bash
# Escaneo completo de seguridad
python tyr.py /ruta/proyecto --plugins nvd,osv --analyzers all

# Escaneo OWASP Top 10
python tyr.py /ruta/proyecto --analyzers sql-injection,xss-detector,auth-checker,command-injection,csrf-protection,path-traversal
```

### Argumentos Personalizados de Analizadores

Cada analizador soporta argumentos personalizados:

```bash
# SQL injection con modo estricto
python tyr.py /ruta --analyzers sql-injection --strict-mode true

# XSS solo patrones React
python tyr.py /ruta --analyzers xss-detector --check-react true --check-dom false

# Secrets con alta entropía
python tyr.py /ruta --analyzers secrets-scanner --min-entropy 5.0

# Code smell con umbrales personalizados
python tyr.py /ruta --analyzers code-smell --max-function-lines 30
```

## Configuración de Plugins

Algunos plugins soportan API keys para mejor rendimiento:

**Plugin NVD:**
```bash
export NVD_API_KEY="tu_api_key_aqui"
python tyr.py /ruta/proyecto --plugins nvd
```

**Plugin GitHub Advisory:**
```bash
export GITHUB_TOKEN="tu_token_aqui"
python tyr.py /ruta/proyecto --plugins github-advisory
```

También puedes pasar API keys por línea de comandos:
```bash
python tyr.py /ruta/proyecto --plugins nvd --nvd-api-key TU_KEY
```

## Crear un Nuevo Plugin

### Opción 1: Plugin de Vulnerabilidades

Crea un nuevo archivo Python en el directorio `plugins/`:

```python
"""
Mi Plugin Personalizado para Tyr
Descripción de lo que hace tu plugin
"""

import time
from typing import Dict, List, Any
import requests
from plugins.base import VulnerabilityPlugin


class MiPluginPersonalizado(VulnerabilityPlugin):
    """Plugin para consultar mi base de datos de vulnerabilidades"""

    @property
    def name(self) -> str:
        return "mi-plugin"

    @property
    def display_name(self) -> str:
        return "Mi Base de Datos de Vulnerabilidades"

    @property
    def description(self) -> str:
        return "Base de datos de vulnerabilidades personalizada"

    @property
    def author(self) -> str:
        return "Tu Nombre"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def requires_api_key(self) -> bool:
        return False

    @property
    def api_key_env_var(self) -> str:
        return "MI_PLUGIN_API_KEY"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.base_url = "https://api.ejemplo.com/v1"
        self.delay = kwargs.get("delay", 1.0)

    def is_available(self) -> bool:
        try:
            response = requests.get(self.base_url, timeout=self.timeout)
            return response.status_code in [200, 401]
        except Exception:
            return False

    def query_vulnerabilidades(
        self, package_name: str, version: str, package_type: str = None
    ) -> List[Dict[str, Any]]:
        """
        Consulta vulnerabilidades para un paquete y versión específicos.
        
        Retorna lista de diccionarios con esta estructura:
        {
            'id': str,              # ID de vulnerabilidad
            'source': str,          # Nombre del plugin
            'description': str,     # Descripción
            'cvss_score': float,    # Score CVSS (0.0-10.0)
            'severity': str,        # CRITICAL, HIGH, MEDIUM, LOW
            'references': List[str], # URLs con más info
            'published': str,       # Fecha de publicación
            'cwe': List[str],       # Identificadores CWE
        }
        """
        vulnerabilidades = []
        
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            response = requests.get(
                f"{self.base_url}/vulnerabilidades",
                params={"package": package_name, "version": version},
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            
            time.sleep(self.delay)
            
            for item in data.get("vulnerabilidades", []):
                vulnerabilidad = {
                    "id": item.get("id", ""),
                    "source": self.name,
                    "description": item.get("description", ""),
                    "cvss_score": item.get("cvss_score", 0.0),
                    "severity": item.get("severity", "UNKNOWN"),
                    "references": item.get("references", []),
                    "published": item.get("published_at", ""),
                    "cwe": item.get("cwe_ids", []),
                }
                vulnerabilidades.append(vulnerabilidad)
            
            return vulnerabilidades
            
        except Exception as e:
            print(f"❌ Error en {self.display_name}: {e}")
            return []
```

### Opción 2: Plugin Analizador de Código

Crea un nuevo archivo Python en el directorio `plugins/`:

```python
"""
Mi Analizador Personalizado para Tyr
Analiza código fuente para problemas de seguridad o calidad
"""

import re
from pathlib import Path
from typing import Dict, List, Any
from plugins.base_analyzer import AnalyzerPlugin


class MiAnalizadorPersonalizado(AnalyzerPlugin):
    """Analizador para detectar patrones personalizados en código"""

    @property
    def name(self) -> str:
        return "mi-analizador"

    @property
    def display_name(self) -> str:
        return "Mi Analizador Personalizado"

    @property
    def description(self) -> str:
        return "Detecta patrones personalizados de seguridad o calidad"

    @property
    def author(self) -> str:
        return "Tu Nombre"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return ['.js', '.ts', '.py', '.php']

    @property
    def plugin_arguments(self) -> Dict[str, Dict[str, Any]]:
        return {
            'strict-mode': {
                'help': 'Habilitar modo estricto para más detecciones',
                'type': bool,
                'default': False,
            },
        }

    def is_available(self) -> bool:
        return True

    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analiza un archivo para el patrón personalizado"""
        hallazgos = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Define patrones a detectar
            patrones = [
                {
                    'pattern': r'tu_patron_aqui',
                    'issue': 'Nombre del Problema',
                    'severity': 'HIGH',
                    'description': 'Descripción del problema',
                    'recommendation': 'Cómo corregirlo',
                },
            ]
            
            for i, line in enumerate(lines, 1):
                for pattern_info in patrones:
                    if re.search(pattern_info['pattern'], line):
                        hallazgos.append({
                            'file': str(file_path),
                            'line': i,
                            'severity': pattern_info['severity'],
                            'category': 'security',  # o 'quality'
                            'issue': pattern_info['issue'],
                            'message': pattern_info['description'],
                            'recommendation': pattern_info['recommendation'],
                            'code_snippet': line.strip()[:100],
                        })
        
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analizando {file_path}: {e}")
        
        return hallazgos
```

## Arquitectura de Plugins

```
plugins/
├── base.py                       # Clase base VulnerabilityPlugin
├── base_analyzer.py              # Clase base AnalyzerPlugin
├── nvd.py                       # Plugin NVD
├── osv.py                       # Plugin OSV
├── github_advisory.py           # Plugin GitHub
├── sql_injection_detector.py   # Detector de inyección SQL
├── xss_detector.py             # Detector de XSS
├── auth_checker.py             # Verificador de auth
├── command_injection_detector.py
├── csrf_protection_checker.py
├── path_traversal_detector.py
├── secrets_scanner.py
├── code_smell_detector.py
└── tu_plugin.py               # Tu plugin personalizado
```

## Ciclo de Vida de los Plugins

### Plugins de Vulnerabilidades
1. **Descubrimiento**: Tyr escanea el directorio `plugins/`
2. **Carga**: Importa módulos y busca subclases de `VulnerabilityPlugin`
3. **Inicialización**: Crea instancias con configuración
4. **Verificación**: Llama a `is_available()`
5. **Consulta**: Llama a `query_vulnerabilities()` para cada dependencia
6. **Agregación**: Combina resultados de todos los plugins

### Plugins Analizadores
1. **Descubrimiento**: Busca subclases de `AnalyzerPlugin`
2. **Descubrimiento de archivos**: Encuentra archivos que coinciden con `supported_extensions`
3. **Análisis**: Llama a `analyze_file()` para cada archivo
4. **Reporte**: Agrega hallazgos por severidad y categoría

## Solución de Problemas

### Plugin No Encontrado
- Asegúrate que el archivo del plugin está en `plugins/`
- El archivo debe terminar en `.py`
- La clase debe heredar de la clase base correcta
- Revisa errores de sintaxis en el código

### Plugin No Disponible
- Revisa la implementación de `is_available()`
- Verifica que el endpoint de API está alcanzable
- Confirma que la API key está configurada si es requerida
- Revisa la conectividad de red

### No Se Encontraron Resultados
- Verifica que los patrones son correctos
- Confirma que las extensiones están en `supported_extensions`
- Asegúrate de usar el nombre correcto del plugin/analizador
- Agrega debug para ver qué está pasando

## Contribuciones

Para contribuir con un nuevo plugin:

1. Haz fork del repositorio
2. Crea tu plugin en el directorio `plugins/`
3. Prueba exhaustivamente con diferentes proyectos
4. Actualiza este README con información del plugin
5. Envía un pull request

---

Para preguntas o problemas con plugins, por favor abre un issue en el repositorio.
