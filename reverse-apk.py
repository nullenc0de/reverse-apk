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
    try:
        subprocess.run(['apktool', 'd', apk_path, '-o', f"{output_dir}/apktool"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"apktool failed: {e}")
    
    try:
        subprocess.run(['d2j-dex2jar', apk_path, '-o', f"{output_dir}/decompiled.jar"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"dex2jar failed: {e}")
    
    try:
        subprocess.run(['jadx', f"{output_dir}/decompiled.jar", '-d', f"{output_dir}/jadx"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"jadx failed: {e}")

def run_nuclei_scan(output_dir: str, target_dir: str, timeout_minutes: int) -> str:
    """Run nuclei scan on a specific directory with optimizations and error handling"""
    logger.info(f"Running optimized nuclei scan on {target_dir}...")
    nuclei_output = f"{output_dir}/nuclei_vulns_{os.path.basename(target_dir)}.txt"

    if os.path.exists(target_dir):
        try:
            command = [
                'nuclei',
                '-o', nuclei_output,
                '-silent',
                '-c', '50',  # Use 50 concurrent workers
                '-rl', '150',  # Rate limit to 150 requests per second
                '-target', target_dir,
                '-t', 'file/android,file/keys',  # Corrected template names
                '-etags', 'info',  # Exclude info severity to focus on more critical issues
                '-timeout', '5',  # Set a 5-second timeout for each template
                '-bulk-size', '25',  # Process 25 targets at a time
                '-project'  # Use project folder for recursive scanning
            ]

            # Run nuclei with a timeout
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=timeout_minutes * 60  # Convert minutes to seconds
                )
                logger.info(f"Nuclei stdout: {result.stdout}")
                logger.info(f"Nuclei stderr: {result.stderr}")
            except subprocess.TimeoutExpired:
                logger.warning(f"Nuclei scan for {target_dir} timed out after {timeout_minutes} minutes. Proceeding with partial results.")

            if os.path.exists(nuclei_output) and os.path.getsize(nuclei_output) > 0:
                logger.info(f"Nuclei scan completed for {target_dir}. Results saved to {nuclei_output}")
                return nuclei_output
            else:
                logger.info(f"Nuclei scan completed for {target_dir} but no vulnerabilities were found.")
                return ""
        except subprocess.CalledProcessError as e:
            logger.error(f"Nuclei scan failed for {target_dir} with return code {e.returncode}")
            logger.error(f"Nuclei stdout: {e.stdout}")
            logger.error(f"Nuclei stderr: {e.stderr}")
    else:
        logger.warning(f"Directory {target_dir} not found for nuclei scan")
    
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

def analyze_apk(apk_path: str, timeout_minutes: int) -> Dict[str, Any]:
    """Analyze an APK file and return the results"""
    temp_dir = extract_apk(apk_path)
    output_dir = os.path.join(temp_dir, "analysis")
    os.makedirs(output_dir, exist_ok=True)

    try:
        decompile_apk(apk_path, output_dir)
        
        # Run separate nuclei scans
        nuclei_outputs = []
        for scan_dir in ['apktool', 'jadx/sources']:
            target_dir = os.path.join(output_dir, scan_dir)
            nuclei_output = run_nuclei_scan(output_dir, target_dir, timeout_minutes)
            if nuclei_output:
                nuclei_outputs.append(nuclei_output)

        manifest_path = os.path.join(output_dir, "apktool", "AndroidManifest.xml")
        if os.path.isfile(manifest_path):
            tree = ET.parse(manifest_path)
            process_manifest(tree)

        if nuclei_outputs:
            analysis["nuclei_results"] = nuclei_outputs

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

    if "nuclei_results" in analysis:
        report += "Nuclei Scan Results:\n"
        for result_file in analysis["nuclei_results"]:
            report += f"Results from {os.path.basename(result_file)}:\n"
            try:
                with open(result_file, 'r') as f:
                    report += f.read()
            except FileNotFoundError:
                report += f"Error: The file {result_file} was not found. The scan may have failed or produced no results.\n"
            report += "\n"
    else:
        report += "No vulnerabilities were found by the Nuclei scan.\n"

    return report

def main(apk_path: str, timeout_minutes: int) -> None:
    """Drive the whole program"""
    results = analyze_apk(apk_path, timeout_minutes)
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
    parser.add_argument("-t", "--timeout", help="timeout for nuclei scan in minutes", type=int, default=60)
    args = parser.parse_args()

    main(args.apk, args.timeout)
