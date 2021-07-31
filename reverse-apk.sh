#!/bin/bash
# + -- --=[ReverseAPK v1.2 by @xer0dayz
# + -- --=[https://xerosecurity.com
#
# ABOUT:
# Quickly analyze and reverse engineer Android applications. SHAMELESSLY STOLEN FROM XER0DAYZ.
# apt-get install unzip smali apktool dex2jar jadx
#
# INSTALL:
# ./install
#
# USAGE:
# reverseapk <appname.apk>
#

OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

echo -e "$OKORANGE                                            "
echo -e "__________                                        "
echo -e "\______   \ _______  __ ___________  ______ ____  "
echo -e " |       _// __ \  \/ // __ \_  __ \/  ___// __ \ "
echo -e " |    |   \  ___/\   /\  ___/|  | \/\___ \\  ___/ "
echo -e " |____|_  /\___  >\_/  \___  >__|  /____  >\___  >"
echo -e "        \/     \/          \/           \/     \/ "
echo -e "                                           _____ __________ ____  __."
echo -e "                                          /  _  \\\\______   \    |/ _|"
echo -e "      --=[( by @xer0dayz )]=--           /  /_\  \|     ___/      <  "
echo -e "   --=[( https://xerosecurity.com )]=-- /    |    \    |   |    |  \ "
echo -e "                                        \____|__  /____|   |____|__ \\"
echo -e "                                                \/                 \/"
echo -e "$RESET"

echo -e "$OKRED Unpacking APK file..."
echo -e "$OKRED=====================================================================$RESET"
unzip $PWD/$1 -d $PWD/$1-unzipped/
baksmali d $PWD/$1-unzipped/classes.dex -o $PWD/$1-unzipped/classes.dex.out/ 2> /dev/null

echo -e "$OKRED Converting APK to Java JAR file..."
echo -e "$OKRED=====================================================================$RESET"
d2j-dex2jar $PWD/$1 -o $PWD/$1.jar --force

echo -e "$OKRED Decompiling using Jadx..."
echo -e "$OKRED=====================================================================$RESET"
jadx $PWD/$1 -j $(grep -c ^processor /proc/cpuinfo) -d $PWD/$1-jadx/ > /dev/null

echo -e "$OKRED Unpacking using APKTool..."
echo -e "$OKRED=====================================================================$RESET"
apktool d $PWD/$1 -o $PWD/$1-unpacked/ -f

nuclei -t /opt/reverse-apk/android -u $PWD/ -c 500 -o $PWD/$1.nuclei_vulns.txt
cat $PWD/$1.nuclei_vulns.txt |egrep "critical]|high]" |sort -k3 > $PWD/$1.crit-high.txt
cat $PWD/$1.nuclei_vulns.txt | egrep "low]|medium]" |sort -k3 > $PWD/$1.low-med.txt
cat $PWD/$1.nuclei_vulns.txt | grep "info]" | egrep -v "url_param|link_finder|relative_links" |sort -k3 > $PWD/$1.info.txt
cat $PWD/$1.nuclei_vulns.txt | egrep "credentials-disclosure]|generic-tokens]|jdbc-connection-string]|jwt-token]|shoppable-token]|aws-access-key]" > $PWD/$1.possible_creds.txt

cat $PWD/$1.nuclei_vulns.txt |grep url_params |cut -d ' ' -f 7 |tr , '\n' | tr ] '\n' | tr [ '\n' |tr -d '"' |tr -d "'" |sort -u > $PWD/$1.params.txt
cat $PWD/$1.nuclei_vulns.txt |grep link_finder |cut -d ' ' -f 7 |tr , '\n' | tr ] '\n' | tr [ '\n' |tr -d '"' |tr -d "'" |sort -u > $PWD/$1.link_finder.txt
cat $PWD/$1.nuclei_vulns.txt |grep relative_links |cut -d ' ' -f 7 |tr , '\n' | tr ] '\n' | tr [ '\n' |tr -d '"' |tr -d "'" |sort -u > $PWD/$1.relative_link.txt

slackcat --channel bugbounty $PWD/$1.crit-high.txt
slackcat --channel bugbounty $PWD/$1.possible_creds.txt
