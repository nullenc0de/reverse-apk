# reverse-apk

Add the Kali Linux repository:

Open the /etc/apt/sources.list file using a text editor with root privileges (e.g., sudo nano /etc/apt/sources.list).
Add the following line at the end of the file:
```
deb http://http.kali.org/kali kali-rolling main non-free contrib
````
Save the file and exit the text editor.

Import the Kali Linux repository GPG key:

Download and import the Kali Linux repository key by running the following command:
```
wget -q -O - https://archive.kali.org/archive-key.asc | sudo apt-key add -
```
Update the package lists:

Run the following command to update the package lists with the newly added Kali repository:
```
sudo apt-get update
```
Install the desired packages:

Run the following command to install the packages you mentioned:
```
sudo apt-get install -y unzip smali apktool dex2jar jadx
```
