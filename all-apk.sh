bbscope bc -b |egrep 'play.google.com|android.com' |cut -d = -f2 |grep com. |cut -d '&' -f1 | cut -d ')' -f1 >scope.txt
bbscope h1 -u nullenc0de -t <token> -b |egrep '\.android' |cut -d = -f2 |anew scope.txt

cat scope.txt | while read apk ; do sleep 30s; python3 /opt/APK-Downloader/apk-downloader.py $apk ;done

ls |while read apk ; do bash reverse-apk-no-nuc.sh $apk > /dev/null; done

nuclei -t ./android -u ./ -c 500 -o ./nuclei_vulns.txt
cat nuclei_vulns.txt |egrep "critical]|high]" |sort -k3 > crit-high.txt
cat nuclei_vulns.txt | egrep "low]|medium]" |sort -k3 > low-med.txt
cat nuclei_vulns.txt | grep "info]" | egrep -v "url_param|link_finder|relative_links" |sort -k3 > info.txt
cat nuclei_vulns.txt | egrep "credentials-disclosure]|generic-tokens]|jdbc-connection-string]|jwt-token]|shoppable-token]|aws-access-key]" > possible_creds.txt

cat nuclei_vulns.txt |grep url_params |cut -d ' ' -f 7 |tr , '\n' | tr ] '\n' | tr [ '\n' |tr -d '"' |tr -d "'" |sort -u > params.txt
cat nuclei_vulns.txt |grep link_finder |cut -d ' ' -f 7 |tr , '\n' | tr ] '\n' | tr [ '\n' |tr -d '"' |tr -d "'" |sort -u > link_finder.txt
cat nuclei_vulns.txt |grep relative_links |cut -d ' ' -f 7 |tr , '\n' | tr ] '\n' | tr [ '\n' |tr -d '"' |tr -d "'" |sort -u > relative_link.txt

slackcat --channel bugbounty crit-high.txt
slackcat --channel bugbounty possible_creds.txt
