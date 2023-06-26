#!/bin/bash

# Check if the required tools are installed
command -v unzip >/dev/null 2>&1 || { echo >&2 "unzip is required but not installed. Aborting."; exit 1; }
command -v java >/dev/null 2>&1 || { echo >&2 "java is required but not installed. Aborting."; exit 1; }
command -v apktool >/dev/null 2>&1 || { echo >&2 "apktool is required but not installed. Aborting."; exit 1; }
command -v d2j-dex2jar >/dev/null 2>&1 || { echo >&2 "d2j-dex2jar is required but not installed. Aborting."; exit 1; }
command -v jadx >/dev/null 2>&1 || { echo >&2 "jadx is required but not installed. Aborting."; exit 1; }
command -v baksmali >/dev/null 2>&1 || { echo >&2 "baksmali is required but not installed. Aborting."; exit 1; }
command -v nuclei >/dev/null 2>&1 || { echo >&2 "nuclei is required but not installed. Aborting."; exit 1; }
command -v slackcat >/dev/null 2>&1 || { echo >&2 "slackcat is required but not installed. Aborting."; exit 1; }

# Prompt for the APK file path
read -p "Enter the path to the APK file: " apk_path

# Create a temporary directory for the decompiled files
temp_dir=$(mktemp -d)

# Unzip the APK file
unzip "$apk_path" -d "$temp_dir"

# Use apktool to decompile the APK
apktool d "$apk_path" -o "$temp_dir/decompiled" -f

# Use d2j-dex2jar to convert the APK to JAR format
d2j-dex2jar "$apk_path" -o "$temp_dir/decompiled.jar"

# Use jadx to decompile the JAR file
jadx "$temp_dir/decompiled.jar" -j "$(grep -c ^processor /proc/cpuinfo)" -d "$temp_dir/jadx-decompiled"

# Use baksmali to decompile the dex files
baksmali d "$apk_path" -o "$temp_dir/baksmali-decompiled"

# Create a folder for the decompiled files
output_dir="$temp_dir/scan_files"
mkdir "$output_dir"

# Move the decompiled and jadx-decompiled files to the output folder
mv "$temp_dir/decompiled" "$output_dir"
mv "$temp_dir/jadx-decompiled" "$output_dir"
mv "$temp_dir/baksmali-decompiled" "$output_dir"

# Run nuclei scan on the decompiled files and store the output
nuclei -t /opt/reverse-apk/android -u "$output_dir" -c 500 -o "$output_dir/nuclei_vulns.txt"

# Process the nuclei output for different categories
filename=$(basename "$apk_path" .apk)
cat "$output_dir/nuclei_vulns.txt" | egrep "critical]|high]" | sort -k3 > "$output_dir/$filename.crit-high.txt"
cat "$output_dir/nuclei_vulns.txt" | egrep "low]|medium]" | sort -k3 > "$output_dir/$filename.low-med.txt"
cat "$output_dir/nuclei_vulns.txt" | grep "info]" | egrep -v "url_param|link_finder|relative_links" | sort -k3 > "$output_dir/$filename.info.txt"
cat "$output_dir/nuclei_vulns.txt" | egrep "credentials-disclosure]|generic-tokens]|jdbc-connection-string]|jwt-token]|shoppable-token]|aws-access-key]" | grep -v 'Ljava/lang/String' > "$output_dir/$filename.possible_creds.txt"
cat "$output_dir/nuclei_vulns.txt" | grep url_params | cut -d ' ' -f 7 | tr , '\n' | tr ] '\n' | tr [ '\n' | tr -d '"' | tr -d "'" | sort -u > "$output_dir/$filename.params.txt"
cat "$output_dir/nuclei_vulns.txt" | grep link_finder | cut -d ' ' -f 7 | tr , '\n' | tr ] '\n' | tr [ '\n' | tr -d '"' | tr -d "'" | sort -u > "$output_dir/$filename.link_finder.txt"
cat "$output_dir/nuclei_vulns.txt" | grep relative_links | cut -d ' ' -f 7 | tr , '\n' | tr ] '\n' | tr [ '\n' | tr -d '"' | tr -d "'" | sort -u > "$output_dir/$filename.relative_link.txt"

# Send the critical/high vulnerabilities and possible credentials to Slack
slackcat --channel bugbounty "$output_dir/$filename.crit-high.txt"
slackcat --channel bugbounty "$output_dir/$filename.possible_creds.txt"

# Clean up temporary files
echo "raw files are in "$temp_dir""
