# Reverse APK Analyzer

A powerful tool for APK analysis, decompilation, and security assessment. This tool combines multiple reverse engineering utilities with security scanning to provide comprehensive APK analysis.

## Features

- 🔍 APK Decompilation with multiple tools
- 🛡️ Security analysis using Nuclei
- 📱 Android Manifest parsing
- 🌐 URL and API endpoint detection
- 📊 Detailed security reporting
- 💾 Comprehensive JSON output

## Installation

### System Requirements
- Python 3.8+
- Java 11+
- Go 1.19+ (for nuclei)
- Linux/Unix environment (recommended) or Windows with WSL

### Complete Installation Commands
```bash
# System dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    default-jdk \
    apktool \
    zipalign \
    adb \
    git \
    wget \
    unzip

# Install dex2jar
cd /opt
wget https://github.com/pxb1988/dex2jar/releases/download/v2.1/dex2jar-2.1.zip
unzip dex2jar-2.1.zip
chmod +x dex2jar-2.1/d2j-dex2jar.sh
sudo ln -s /opt/dex2jar-2.1/d2j-dex2jar.sh /usr/local/bin/d2j-dex2jar

# Install jadx
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip
chmod +x jadx/bin/jadx
sudo ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# Install Go and set path
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Python dependencies
pip3 install lxml typing-extensions urllib3

# Clone and prepare the tool
cd /opt
git clone https://github.com/nullenc0de/reverse-apk.git
cd reverse-apk
chmod +x reverse-apk.py
```

## Getting APKs for Analysis

### From Google Play Store
1. Visit [Evozi APK Downloader](https://apps.evozi.com/apk-downloader/)
2. Get the Google Play URL or package name (e.g., com.example.app)
3. Download the APK

### Alternative APK Sources
- [APKMirror](https://www.apkmirror.com/) - Verified APKs
- [APKPure](https://apkpure.com/) - Large collection

## Usage

### Basic Usage
```bash
python3 reverse-apk.py -a path/to/your.apk -t 30
```

### Command Line Options
```
-a, --apk     : Path to the APK file (required)
-t, --timeout : Timeout for nuclei scan in minutes (default: 60)
```

### Output Files Generated
1. `<package>_report.txt`: Human-readable security report
2. `<package>_analysis.json`: Detailed JSON analysis data

## Analysis Features

### Static Analysis
- APK Decompilation
- Manifest Analysis
- Permission Checking
- Component Analysis
- URL/Endpoint Discovery

### Security Checks
- Certificate Analysis
- Security Configuration Review
- Permission Assessment
- Component Export Analysis
- Nuclei Security Scans

## Troubleshooting

### Common Issues and Fixes

1. Tool Path Issues:
```bash
# Add tools to path
echo 'export PATH=$PATH:/opt/dex2jar-2.1:/opt/jadx/bin:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

2. Permission Issues:
```bash
# Fix permissions
sudo chown -R $USER:$USER /opt/dex2jar-2.1
sudo chown -R $USER:$USER /opt/jadx
chmod +x reverse-apk.py
```

3. Memory Issues:
```bash
# Increase jadx memory
echo 'export JADX_OPTS="-Xmx4g"' >> ~/.bashrc
source ~/.bashrc
```

4. Java Version:
```bash
# Check Java version
java -version

# Set JAVA_HOME if needed
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

## Validation

```bash
# Verify all tools are installed correctly
python3 --version
java -version
apktool --version
d2j-dex2jar --version
jadx --version
nuclei -version
```

## Example Report Output

```
Security Analysis Report for com.example.app

Version: 1.0.0
Min SDK Version: 21
Target SDK Version: 30
Debuggable: false
Allow Backup: true

Permissions:
  - android.permission.INTERNET
  - android.permission.ACCESS_NETWORK_STATE

Exported Components:
  - activity: com.example.MainActivity
  - receiver: com.example.BootReceiver

URLs Found:
  - https://api.example.com/v1
  - https://cdn.example.com/assets
```

## Legal Disclaimer

```
IMPORTANT:
- Only analyze APKs you have permission to examine
- Respect application terms of service
- Use for educational purposes only
- Some apps may have anti-reverse engineering measures
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

Need help? 
- Open an issue on [GitHub](https://github.com/nullenc0de/reverse-apk/issues)
- Check existing issues for solutions
- Include detailed error messages when reporting problems

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

- [apktool](https://ibotpeaches.github.io/Apktool/)
- [dex2jar](https://github.com/pxb1988/dex2jar)
- [jadx](https://github.com/skylot/jadx)
- [nuclei](https://github.com/projectdiscovery/nuclei)

## Security Notice

Report security vulnerabilities responsibly through GitHub's security advisory feature.

---
Made with ❤️ by nullenc0de
