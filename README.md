# APK Analyzer

## Overview

The APK Analyzer is a Python tool designed to perform security analysis on Android APK files. It extracts, decompiles, and analyzes APK contents to identify potential security issues and gather relevant information about the APK. This tool also runs a security scan using Nuclei and generates detailed reports based on the analysis.

## Features

- APK Extraction: Extracts APK contents to a temporary directory
- APK Decompilation: Decompiles APK files using Apktool, dex2jar, and jadx
- Nuclei Scan: Runs a Nuclei scan on the decompiled files to detect vulnerabilities
- Manifest Analysis: Extracts and analyzes security-relevant information from the AndroidManifest.xml file
- URL Extraction: Identifies URLs, JavaScript URLs, and potential API endpoints from decompiled files
- Report Generation: Generates a human-readable report and JSON output based on the analysis results

## Requirements

- Python 3.6 or later
- apktool: For decompiling APK files
- d2j-dex2jar: For converting DEX files to JAR
- jadx: For decompiling JAR files to Java source code
- nuclei: For vulnerability scanning

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/nullenc0de/apk-analyzer.git
   ```

2. Navigate to the project directory:
   ```
   cd apk-analyzer
   ```

3. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

4. Ensure that apktool, d2j-dex2jar, jadx, and nuclei are installed and available in your PATH.

## Usage

To analyze an APK file, run the following command:

```
python apk_analyzer.py -a /path/to/your.apk
```

Replace `/path/to/your.apk` with the path to the APK file you want to analyze.

## Output

Two files will be generated:

1. Report: A human-readable report will be saved as `{package_name}_report.txt`
2. Analysis: A JSON file containing detailed analysis results will be saved as `{package_name}_analysis.json`

## Example

```
python apk_analyzer.py -a /path/to/sample.apk
```

This command will analyze `sample.apk`, generate a report, and save the results in JSON format.

## Functions

- `extract_apk(apk_path: str) -> str`: Extracts APK contents to a temporary directory.
- `decompile_apk(apk_path: str, output_dir: str) -> None`: Decompiles APK using Apktool, dex2jar, and jadx.
- `run_nuclei_SCAN(output_dir: str) -> str`: Runs a Nuclei scan on the decompiled files and returns the path to the results file.
- `process_manifest(tree: ET.ElementTree) -> None`: Processes the Android manifest and extracts security-relevant information.
- `extract_urls_and_endpoints(decompiled_dir: str) -> Tuple[Set[str], Set[str], Set[str]]`: Extracts URLs, JavaScript URLs, and potential API endpoints from decompiled files.
- `analyze_apk(apk_path: str) -> Dict[str, Any]`: Analyzes an APK file and returns the results as a dictionary.
- `generate_report(analysis: Dict[str, Any]) -> str`: Generates a human-readable report from the analysis results.
- `main(apk_path: str) -> None`: Drives the whole program, performing analysis and generating reports.

## Contributing

Feel free to open issues or submit pull requests if you find bugs or want to add new features. Contributions are welcome!

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
