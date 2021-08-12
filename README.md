# reverse-apk
```
apt-get install unzip smali apktool dex2jar jadx

export GOPATH=/opt/bbscope
go get -u github.com/sw33tLie/bbscope
ln -s /opt/bbscope/bin/bbscope /usr/local/bin/bbscope

export GOPATH=/opt/anew
go get -u github.com/tomnomnom/anew
ln -s /opt/anew/bin/anew /usr/local/bin/anew

export GOPATH=/opt/nuclei
go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
ln -s /opt/nuclei/bin/nuclei /usr/local/bin/nuclei

git clone https://github.com/ko2sec/apkizer.git || git -C /opt/ko2sec pull
cd ko2sec
pip3 install -r requirements.txt
cd ..
```
