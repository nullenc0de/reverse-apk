import xml.etree.ElementTree as ET
import argparse
import os
import sys
import json
import logging
import tempfile
import zipfile
import shutil
import subprocess
import re
import urllib.parse
from typing import Dict, List, Any, Set, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

xmlns = "{http://schemas.android.com/apk/res/android}"
analysis: Dict[str, Any] = {}

def extract_apk(apk_path: str) -> str:
    """Extract APK contents to a temporary directory"""
    temp_dir = tempfile.mkdtemp()
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)
    return temp_dir

def decompile_apk(apk_path: str, output_dir: str) -> None:
    """Decompile APK using various tools"""
    logger.info("Decompiling APK...")
    subprocess.run(['apktool', 'd', apk_path, '-o', f"{output_dir}/apktool"], check=True)
    subprocess.run(['d2j-dex2jar', apk_path, '-o', f"{output_dir}/decompiled.jar"], check=True)
    subprocess.run(['jadx', f"{output_dir}/decompiled.jar", '-d', f"{output_dir}/jadx"], check=True)

def run_nuclei_scan(output_dir: str) -> str:
    """Run nuclei scan on specific directories of the decompiled files"""
    logger.info("Running nuclei scan...")
    nuclei_output = f"{output_dir}/nuclei_vulns.txt"

    scan_dirs = [
        f"{output_dir}/apktool",
        f"{output_dir}/jadx/sources",
    ]

    # Filter directories that exist and convert to absolute paths
    valid_dirs = [os.path.abspath(dir) for dir in scan_dirs if os.path.exists(dir)]

    if valid_dirs:
        try:
            logger.info(f"Scanning directories: {', '.join(valid_dirs)}")

            # Build the nuclei command with multiple -target arguments
            command = ['nuclei', '-o', nuclei_output, '-v']
            for dir in valid_dirs:
                command.extend(['-target', dir])
            command.extend(['-t', 'file/android,file/keys'])

            # Run nuclei
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )

            # Log the command output
            logger.info(f"Nuclei stdout: {result.stdout}")
            logger.info(f"Nuclei stderr: {result.stderr}")

            if os.path.exists(nuclei_output) and os.path.getsize(nuclei_output) > 0:
                logger.info(f"Nuclei scan completed. Results saved to {nuclei_output}")
                return nuclei_output
            else:
                logger.info("Nuclei scan completed but no vulnerabilities were found.")
                return ""
        except subprocess.CalledProcessError as e:
            logger.error(f"Nuclei scan failed with return code {e.returncode}")
            logger.error(f"Nuclei stdout: {e.stdout}")
            logger.error(f"Nuclei stderr: {e.stderr}")
            return ""
    else:
        logger.warning("No valid directories found for nuclei scan")
        return ""

def process_manifest(tree: ET.ElementTree) -> None:
    """Process the Android manifest and extract security-relevant information"""
    root = tree.getroot()

    analysis["package"] = root.get("package", "Unknown")
    analysis["version"] = root.get(f"{xmlns}versionName", "Unknown")
    analysis["min_sdk"] = root.find("./uses-sdk").get(f"{xmlns}minSdkVersion", "Unknown") if root.find("./uses-sdk") is not None else "Unknown"
    analysis["target_sdk"] = root.find("./uses-sdk").get(f"{xmlns}targetSdkVersion", "Unknown") if root.find("./uses-sdk") is not None else "Unknown"

    application = root.find("application")
    if application is not None:
        analysis["debuggable"] = application.get(f"{xmlns}debuggable", "false")
        analysis["allowBackup"] = application.get(f"{xmlns}allowBackup", "true")
        analysis["network_security_config"] = application.get(f"{xmlns}networkSecurityConfig", "Not set")

    analysis["permissions"] = [perm.get(f"{xmlns}name") for perm in root.findall("uses-permission")]

    analysis["exported_components"] = []
    for component in ["activity", "service", "receiver", "provider"]:
        for elem in root.findall(f"./application/{component}"):
            if elem.get(f"{xmlns}exported") == "true":
                analysis["exported_components"].append({
                    "type": component,
                    "name": elem.get(f"{xmlns}name"),
                })

def extract_urls_and_endpoints(decompiled_dir: str) -> Tuple[Set[str], Set[str], Set[str]]:
    """Extract URLs, JavaScript URLs, and potential API endpoints from decompiled files"""
    urls = set()
    js_urls = set()
    api_endpoints = set()

    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(('.java', '.xml', '.smali')):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Extract URLs
                    found_urls = re.findall(r'https?://[^\s/$.?#].[^\s]*', content)
                    urls.update(found_urls)

                    # Identify JavaScript URLs
                    js_found = [url for url in found_urls if url.lower().endswith('.js')]
                    js_urls.update(js_found)

                    # Extract potential API endpoints
                    api_patterns = [
                        r'/api/[a-zA-Z0-9-_/]+',
                        r'/v\d+/[a-zA-Z0-9-_/]+',
                        r'/rest/[a-zA-Z0-9-_/]+'
                    ]
                    for pattern in api_patterns:
                        endpoints = re.findall(pattern, content)
                        api_endpoints.update(endpoints)

    return urls, js_urls, api_endpoints

def analyze_apk(apk_path: str) -> Dict[str, Any]:
    """Analyze an APK file and return the results"""
    temp_dir = extract_apk(apk_path)
    output_dir = os.path.join(temp_dir, "analysis")
    os.makedirs(output_dir, exist_ok=True)

    try:
        decompile_apk(apk_path, output_dir)
        nuclei_output = run_nuclei_scan(output_dir)

        manifest_path = os.path.join(output_dir, "apktool", "AndroidManifest.xml")
        if os.path.isfile(manifest_path):
            tree = ET.parse(manifest_path)
            process_manifest(tree)

        if nuclei_output:
            analysis["nuclei_results"] = nuclei_output

        urls, js_urls, api_endpoints = extract_urls_and_endpoints(output_dir)
        analysis["urls"] = list(urls)
        analysis["js_urls"] = list(js_urls)
        analysis["api_endpoints"] = list(api_endpoints)

        return analysis
    finally:
        shutil.rmtree(temp_dir)

def generate_report(analysis: Dict[str, Any]) -> str:
    """Generate a human-readable report from the analysis results"""
    report = f"Security Analysis Report for {analysis.get('package', 'Unknown Package')}\n\n"

    report += f"Version: {analysis.get('version', 'Unknown')}\n"
    report += f"Min SDK Version: {analysis.get('min_sdk', 'Unknown')}\n"
    report += f"Target SDK Version: {analysis.get('target_sdk', 'Unknown')}\n"
    report += f"Debuggable: {analysis.get('debuggable', 'Unknown')}\n"
    report += f"Allow Backup: {analysis.get('allowBackup', 'Unknown')}\n"
    report += f"Network Security Config: {analysis.get('network_security_config', 'Not set')}\n\n"

    report += "Permissions:\n"
    for perm in analysis.get('permissions', []):
        report += f"  - {perm}\n"
    report += "\n"

    report += "Exported Components:\n"
    for component in analysis.get('exported_components', []):
        report += f"  - {component['type']}: {component['name']}\n"
    report += "\n"

    report += "URLs Found:\n"
    for url in analysis.get('urls', []):
        report += f"  - {url}\n"
    report += "\n"

    report += "JavaScript URLs Found:\n"
    for url in analysis.get('js_urls', []):
        report += f"  - {url}\n"
    report += "\n"

    report += "Potential API Endpoints:\n"
    for endpoint in analysis.get('api_endpoints', []):
        report += f"  - {endpoint}\n"
    report += "\n"

    if "nuclei_results" in analysis and analysis["nuclei_results"]:
        report += "Nuclei Scan Results:\n"
        with open(analysis['nuclei_results'], 'r') as f:
            report += f.read()
    else:
        report += "No vulnerabilities were found by the Nuclei scan.\n"

    return report

def main(apk_path: str) -> None:
    """Drive the whole program"""
    results = analyze_apk(apk_path)
    report = generate_report(results)

    report_filename = f"{results.get('package', 'unknown')}_report.txt"
    with open(report_filename, "w") as f:
        f.write(report)

    analysis_filename = f"{results.get('package', 'unknown')}_analysis.json"
    with open(analysis_filename, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Analysis complete. Report saved as {report_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APK Analyzer")
    parser.add_argument("-a", "--apk", help="path to the APK file", required=True)
    args = parser.parse_args()

    main(args.apk)
