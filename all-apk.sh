bbscope bc -b |egrep 'play.google.com|android.com' |cut -d = -f2 |grep com. |cut -d '&' -f1 | cut -d ')' -f1 >scope.txt
bbscope h1 -u nullenc0de -t <token> -b |egrep '\.android' |cut -d = -f2 |anew scope.txt

cat scope.txt | while read apk ; do bash /opt/reverse-apk/reverse-apk.sh $apk > /dev/null; done
