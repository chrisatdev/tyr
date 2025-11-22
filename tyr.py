#!/usr/bin/env python3
import argparse
import json
import re
import signal
import sys
import time
from pathlib import Path

import requests

# Versión del proyecto
__version__ = "1.0.0"


# Códigos de color ANSI
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


# Banner mejorado de Tyr
BANNER = f"""
{Colors.GREEN}
╔══════════════════════════════════════════╗
║                                          ║
║        ████████╗██╗   ██╗██████╗         ║
║        ╚══██╔══╝╚██╗ ██╔╝██╔══██╗        ║
║           ██║    ╚████╔╝ ██████╔╝        ║
║           ██║     ╚██╔╝  ██╔══██╗        ║
║           ██║      ██║   ██║  ██║        ║
║           ╚═╝      ╚═╝   ╚═╝  ╚═╝        ║
║                                          ║
║         Security Scanner v{__version__}          ║
║          by Christian Benitez            ║
║         cbenitezdiaz@gmail.com           ║
║                                          ║
╚══════════════════════════════════════════╝
{Colors.RESET}
"""


class NVDClient:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        # Con API key: 0.6 segundos (50 requests por 30 segundos)
        # Sin API key: 6 segundos (5 requests por 30 segundos)
        # Cualquier consulta adicional puede resultar en bloqueo temporal
        # eso ya depende de la API de NVD
        self.delay = 0.6 if api_key else 6

    def search_cve(self, package_name, version):
        """Busca CVEs para un paquete y versión específicos"""
        time.sleep(self.delay)

        params = {"keywordSearch": package_name, "resultsPerPage": 20}

        # Agregar API key a los headers si está disponible
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(
                self.base_url, params=params, headers=headers, timeout=30
            )
            if response.status_code == 200:
                return self.parse_cves(response.json(), package_name, version)
            elif response.status_code == 403:
                raise Exception("Rate limit exceeded. Consider using an API key.")
            else:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
        except Exception as e:
            raise Exception(f"Error consultando NVD para {package_name}: {str(e)}")

    def parse_cves(self, data, package_name, version):
        """Parse los resultados de la API del NVD"""
        vulnerabilities = []

        if "vulnerabilities" not in data:
            return vulnerabilities

        for vuln in data["vulnerabilities"]:
            cve = vuln["cve"]
            cve_id = cve["id"]

            # Verificar si esta CVE afecta a nuestra versión específica
            if self.affects_version(cve, package_name, version):
                vulnerability = {
                    "cve": cve_id,
                    "description": self.get_description(cve),
                    "severity": self.get_severity(cve),
                    "type": self.get_vulnerability_type(cve),
                    "remediation": self.get_remediation(cve_id),
                    "cvss_score": self.get_cvss_score(cve),
                }
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def affects_version(self, cve, package_name, version):
        """Verifica si la CVE afecta a la versión específica"""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc["lang"] == "en":
                description_text = desc["value"].lower()
                if package_name.lower() in description_text and any(
                    char.isdigit() for char in description_text
                ):
                    return True
        return True  # Asumir que afecta si no podemos determinar con precisión

    def get_description(self, cve):
        """Obtiene la descripción en inglés de la CVE"""
        for desc in cve.get("descriptions", []):
            if desc["lang"] == "en":
                return desc["value"]
        return "No description available"

    def get_severity(self, cve):
        """Obtiene la severidad CVSS v3 si está disponible"""
        metrics = cve.get("metrics", {})

        # Buscar CVSS v3 primero
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            base_score = cvss_data.get("baseScore", 0)
            return self.score_to_severity(base_score)
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            base_score = cvss_data.get("baseScore", 0)
            return self.score_to_severity(base_score)
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            base_score = cvss_data.get("baseScore", 0)
            return self.score_to_severity_v2(base_score)

        return "UNKNOWN"

    def get_cvss_score(self, cve):
        """Obtiene el puntaje CVSS numérico"""
        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", 0)
        elif "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", 0)
        elif "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0)

        return 0.0

    def score_to_severity(self, score):
        """Convierte puntuación CVSS v3 a severidad"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "NONE"

    def score_to_severity_v2(self, score):
        """Convierte puntuación CVSS v2 a severidad"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "NONE"

    def get_vulnerability_type(self, cve):
        """Determina el tipo de vulnerabilidad basado en la descripción"""
        description = self.get_description(cve).lower()
        if "buffer overflow" in description or "overflow" in description:
            return "Buffer Overflow"
        elif "sql injection" in description or "sqli" in description:
            return "SQL Injection"
        elif "cross-site" in description or "xss" in description:
            return "Cross-Site Scripting"
        elif "denial of service" in description or "dos" in description:
            return "Denial of Service"
        elif "code execution" in description or "rce" in description:
            return "Remote Code Execution"
        elif "information disclosure" in description:
            return "Information Disclosure"
        else:
            return "Vulnerability"

    def get_remediation(self, cve_id):
        """Genera recomendación de remediación"""
        return "Update to a patched version"


def signal_handler(sig, frame):
    """Manejador para Ctrl+C"""
    print(
        f"\n{Colors.YELLOW}[!] Escaneo interrumpido por el usuario. Saliendo...{
            Colors.RESET
        }"
    )
    sys.exit(1)


def parse_arguments():
    """Configura y parsea los argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}Tyr - Escáner de Vulnerabilidades v{__version__}{
            Colors.RESET
        }",
        epilog='Ejemplo: python3 tyr.py /ruta/proyecto -n "Mi Proyecto" -o reporte.md',
        add_help=False,
    )

    parser.add_argument("project_path", nargs="?", help="Ruta del proyecto a escanear")
    parser.add_argument(
        "-n", "--project-name", help="Nombre del proyecto para el reporte"
    )
    parser.add_argument(
        "-o", "--output", default="tyr_report.md", help="Nombre del archivo de salida"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso")
    parser.add_argument(
        "-k", "--api-key", help="API Key para NVD (reduce el delay entre requests)"
    )
    parser.add_argument(
        "-h", "--help", action="store_true", help="Mostrar esta ayuda y salir"
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Mostrar versión y salir"
    )

    return parser.parse_args()


def show_help():
    """Muestra la ayuda con el banner"""
    print(BANNER)
    print(f"{Colors.CYAN}Uso: python3 tyr.py [RUTA_PROYECTO] [OPCIONES]{Colors.RESET}")
    print(f"\n{Colors.YELLOW}Opciones:{Colors.RESET}")
    print("  -n, --project-name NAME  Nombre del proyecto para el reporte")
    print(
        "  -o, --output FILE        Nombre del archivo de salida (default: tyr_report.md)"
    )
    print("  -q, --quiet              Modo silencioso")
    print(
        "  -k, --api-key KEY        API Key para NVD (reduce el delay entre requests)"
    )
    print("  -h, --help               Mostrar esta ayuda y salir")
    print("  -v, --version            Mostrar versión y salir")
    print(f"\n{Colors.YELLOW}Ejemplos:{Colors.RESET}")
    print("  python3 tyr.py /ruta/proyecto")
    print('  python3 tyr.py /ruta/proyecto -n "Mi App" -o seguridad.md')
    print("  python3 tyr.py /ruta/proyecto -q")
    print("  python3 tyr.py /ruta/proyecto -k TU_API_KEY_NVD")


def show_version():
    """Muestra la versión"""
    print(f"Tyr v{__version__}")


def find_dependency_files(root_path):
    """Encuentra archivos de dependencias de forma recursiva"""
    target_files = []
    patterns = [
        "**/package.json",
        "**/composer.json",
        "**/requirements.txt",
        "**/Gemfile",
        "**/Dockerfile",
        "**/pom.xml",
        "**/build.gradle",
        "**/Cargo.toml",
    ]

    for pattern in patterns:
        try:
            target_files.extend(Path(root_path).glob(pattern))
        except Exception as e:
            if not args.quiet:
                print(f"Error buscando {pattern}: {str(e)}")

    return [f for f in target_files if f.is_file()]


def parse_dependencies(file_path):
    """Parsea dependencias de diferentes tipos de archivos"""
    dependencies = {}

    try:
        if file_path.name == "package.json":
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                deps = {
                    **data.get("dependencies", {}),
                    **data.get("devDependencies", {}),
                }
                for pkg, version in deps.items():
                    clean_version = clean_version_string(version)
                    if clean_version:
                        dependencies[pkg] = clean_version

        elif file_path.name == "composer.json":
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for pkg, version in data.get("require", {}).items():
                    clean_version = clean_version_string(version)
                    if clean_version and not pkg == "php":
                        dependencies[pkg] = clean_version

        elif file_path.name == "requirements.txt":
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "==" in line:
                        parts = line.split("==")
                        if len(parts) == 2:
                            pkg, version = parts[0].strip(), parts[1].strip()
                            dependencies[pkg] = version

        elif file_path.name == "Gemfile":
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    match = re.search(
                        r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?",
                        line,
                    )
                    if match:
                        pkg = match.group(1)
                        version = match.group(2) if match.group(2) else "unknown"
                        dependencies[pkg] = clean_version_string(version)

        elif file_path.name == "Dockerfile":
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("FROM"):
                        base_image = line.strip().split()[1]
                        dependencies["base_image"] = (
                            base_image.split(":")[-1] if ":" in base_image else "latest"
                        )

        elif file_path.name == "pom.xml":
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Buscar dependencias en pom.xml
                dependencies_pattern = r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>"
                matches = re.findall(dependencies_pattern, content, re.DOTALL)
                for group_id, artifact_id, version in matches:
                    pkg = f"{group_id}:{artifact_id}"
                    clean_version = clean_version_string(version)
                    if clean_version:
                        dependencies[pkg] = clean_version

    except Exception as e:
        if not args.quiet:
            print(f"Error parsing {file_path}: {str(e)}")

    return dependencies


def clean_version_string(version):
    """Limpia cadenas de versión de caracteres especiales"""
    if not version or version == "unknown":
        return None

    # Remover caracteres especiales comunes
    clean = re.sub(r"[\^~>=<*]", "", version)
    # Tomar solo la parte antes del guión
    clean = re.sub(r"[^\d\.]", "", clean.split("-")[0])

    if clean and any(c.isdigit() for c in clean):
        return clean
    return None


def check_vulnerabilities(dependencies, nvd_client):
    """Busca vulnerabilidades usando NVD"""
    vulnerabilities = []

    for package, version in dependencies.items():
        if not version or package == "base_image":
            continue

        if not args.quiet:
            print(f"  Verificando {package} {version}...")

        try:
            package_vulns = nvd_client.search_cve(package, version)
        except Exception as e:
            if not args.quiet:
                print(
                    f"  {Colors.RED}Error consultando {package}: {str(e)}{Colors.RESET}"
                )
            continue

        for vuln in package_vulns:
            vulnerabilities.append(
                {
                    "package": package,
                    "version": version,
                    "cve": vuln["cve"],
                    "severity": vuln["severity"],
                    "type": vuln["type"],
                    "remediation": vuln["remediation"],
                    "description": vuln["description"],
                    "cvss_score": vuln["cvss_score"],
                }
            )

    return vulnerabilities


def sort_vulnerabilities(vulnerabilities):
    """Ordena vulnerabilidades por severidad (CRITICAL primero)"""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return sorted(
        vulnerabilities,
        key=lambda x: (severity_order.get(x["severity"], 5), x["cvss_score"]),
        reverse=True,
    )


def get_severity_color(severity):
    """Devuelve el color correspondiente a la severidad"""
    colors = {
        "CRITICAL": Colors.RED,
        "HIGH": Colors.MAGENTA,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.BLUE,
        "UNKNOWN": Colors.WHITE,
    }
    return colors.get(severity, Colors.WHITE)


def smart_truncate(text, max_length=100):
    """Truncamiento inteligente que limpia caracteres problemáticos y mantiene palabras completas"""
    if not text:
        return ""

    # Limpiar caracteres problemáticos:
    # comillas, dos puntos, saltos de línea, etc.
    clean_text = re.sub(r'[\n\r\t:"\']+', " ", str(text))
    # Colapsar múltiples espacios en uno solo
    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    if len(clean_text) <= max_length:
        return clean_text

    # Truncar y buscar el último espacio antes del límite
    truncated = clean_text[:max_length]
    last_space = truncated.rfind(" ")

    if (
        last_space > max_length * 0.7
    ):  # Si encontramos un espacio en una posición razonable
        return truncated[:last_space] + "..."
    else:
        return truncated + "..."


def sort_vulnerabilities(vulnerabilities):
    """Ordena vulnerabilidades por severidad (CRITICAL primero)"""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return sorted(vulnerabilities, key=lambda x: severity_order.get(x["severity"], 5))


def generate_report(vulnerabilities, project_name, output_file, total_dependencies):
    """Genera reporte en formato Markdown"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# 🛡️ Reporte de Vulnerabilidades - {project_name}\n\n")
        f.write(f"**Fecha de análisis:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Total de dependencias analizadas:** {total_dependencies}\n")
        f.write(f"**Vulnerabilidades encontradas:** {len(vulnerabilities)}\n\n")

        if not vulnerabilities:
            f.write("## ✅ No se encontraron vulnerabilidades\n")
            return

        # Ordenar vulnerabilidades por severidad
        vulnerabilities = sort_vulnerabilities(vulnerabilities)

        # Resumen por severidad
        severity_count = {}
        for vuln in vulnerabilities:
            severity_count[vuln["severity"]] = (
                severity_count.get(vuln["severity"], 0) + 1
            )

        f.write("## 📊 Resumen por Severidad\n\n")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_count.get(severity, 0)
            if count > 0:
                f.write(f"- **{severity}**: {count}\n")
        f.write("\n")

        f.write("## 🔍 Vulnerabilidades Detalladas\n\n")
        f.write(
            "| Severidad | Paquete | Versión | CVE | Tipo | Descripción | Remediation |\n"
        )
        f.write(
            "|-----------|---------|---------|-----|------|-------------|-------------|\n"
        )

        # Colores para cada nivel de severidad
        severity_colors = {
            "CRITICAL": "#FF4444",  # Rojo intenso
            "HIGH": "#FF6B35",  # Naranja rojizo
            "MEDIUM": "#FFA500",  # Naranja
            "LOW": "#4CAF50",  # Verde
            "UNKNOWN": "#757575",  # Gris
        }

        for vuln in vulnerabilities:
            # Enlace al CVE que se abre en nueva pestaña
            # El sitio de NVD puede tardar en cargar en algunos casos
            cve_link = (
                f"[{vuln['cve']}](https://nvd.nist.gov/vuln/detail/{vuln['cve']})"
            )
            # Truncamiento inteligente de la descripción
            short_desc = smart_truncate(vuln["description"])

            # Severidad con color HTML
            color = severity_colors.get(vuln["severity"], "#000000")
            severity_html = f'<span style="color: {color}; font-weight: bold;">{
                vuln["severity"]
            }</span>'

            f.write(
                f"| {severity_html} | {vuln['package']} | {vuln['version']} | {
                    cve_link
                } | {vuln['type']} | {short_desc} | {vuln['remediation']} |\n"
            )


def main():
    global args
    args = parse_arguments()

    # Registrar manejador para Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Mostrar versión si se solicita
    if args.version:
        show_version()
        sys.exit(0)

    # Mostrar ayuda si no hay argumentos o si se solicita ayuda
    if args.help or not args.project_path:
        show_help()
        sys.exit(0)

    if not args.quiet:
        print(BANNER)
        print(
            f"{Colors.CYAN}Tyr - Escáner de Vulnerabilidades v{__version__}{Colors.RESET}"
        )
        print("=" * 50)

    project_path = Path(args.project_path)
    if not project_path.exists():
        print(f"{Colors.RED}❌ La ruta del proyecto no existe{Colors.RESET}")
        sys.exit(1)

    project_name = args.project_name or project_path.name

    # Inicializar cliente NVD con API key si se proporciona
    nvd_client = NVDClient(api_key=args.api_key)

    if not args.quiet:
        if args.api_key:
            print(
                f"{Colors.GREEN}✅ Usando API Key de NVD (delay reducido){Colors.RESET}"
            )
        else:
            print(
                f"{Colors.YELLOW}⚠️  Sin API Key de NVD (delay aumentado){Colors.RESET}"
            )
        print(f"🔍 Escaneando proyecto: {project_name}")
        print(f"📁 Ruta: {project_path}")

    # Buscar archivos de dependencias
    dependency_files = find_dependency_files(project_path)

    if not dependency_files:
        if not args.quiet:
            print("❌ No se encontraron archivos de dependencias")
        sys.exit(1)

    if not args.quiet:
        print(f"📄 Archivos encontrados: {len(dependency_files)}")

    # Recolectar todas las dependencias
    all_dependencies = {}
    for file in dependency_files:
        if not args.quiet:
            print(f"📋 Analizando: {file}")
        dependencies = parse_dependencies(file)
        all_dependencies.update(dependencies)

    if not args.quiet:
        print(f"📦 Dependencias encontradas: {len(all_dependencies)}")
        print(f"\n{Colors.YELLOW}🔍 Buscando vulnerabilidades...{Colors.RESET}")
        if args.api_key:
            print("✅ API Key")
        else:
            print("⚠️  Sin API Key")
        print()

    # Buscar vulnerabilidades
    try:
        vulnerabilities = check_vulnerabilities(all_dependencies, nvd_client)
    except Exception as e:
        print(f"{Colors.RED}❌ Error durante el análisis: {str(e)}{Colors.RESET}")
        sys.exit(1)

    # Ordenar vulnerabilidades por severidad
    vulnerabilities = sort_vulnerabilities(vulnerabilities)

    # Generar reporte
    generate_report(vulnerabilities, project_name, args.output, len(all_dependencies))

    # Mostrar resultados
    if not args.quiet:
        if vulnerabilities:
            print(
                f"\n{Colors.RED}🚨 Vulnerabilidades encontradas: {len(vulnerabilities)}{
                    Colors.RESET
                }"
            )
            print(f"📊 Reporte generado: {args.output}")

            # Mostrar resumen con colores
            severity_count = {}
            for vuln in vulnerabilities:
                severity_count[vuln["severity"]] = (
                    severity_count.get(vuln["severity"], 0) + 1
                )

            print(f"\n{Colors.CYAN}📈 Resumen:{Colors.RESET}")
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_count.get(severity, 0)
                if count > 0:
                    color = get_severity_color(severity)
                    print(f"  {color}{severity}: {count}{Colors.RESET}")

            # Mostrar detalles con colores
            print(f"\n{Colors.CYAN}📋 Detalles de vulnerabilidades:{Colors.RESET}")
            for vuln in vulnerabilities:
                color = get_severity_color(vuln["severity"])
                print(
                    f"\n{color}▶ {vuln['package']} {vuln['version']} - {
                        vuln['severity']
                    } (CVSS: {vuln['cvss_score']}){Colors.RESET}"
                )
                print(f"  CVE: {vuln['cve']}")
                print(f"  Tipo: {vuln['type']}")
                description_short = smart_truncate(vuln["description"], 150)
                print(f"  Descripción: {description_short}")
                print(f"  Remediation: {vuln['remediation']}")
        else:
            print(f"{Colors.GREEN}✅ No se encontraron vulnerabilidades.{Colors.RESET}")
            print(f"📊 Reporte generado: {args.output}")
    else:
        print("Análisis finalizado")


if __name__ == "__main__":
    main()
    # main()
