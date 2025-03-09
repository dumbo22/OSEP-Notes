' Credit: Github.com/leo4j

Sub AutoOpen()

    strComputer = "."
    Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
    Set colItems = objWMIService.ExecQuery("Select * from Win32_Processor")
    
    For Each objItem In colItems
        architecture = objItem.architecture ' Get the system architecture (either 9 for 64-bit or 0 for 32-bit)
        Exit For ' We only need to check the first processor, so exit the loop
    Next
            
    Dim Shell As Object
    Set Shell = CreateObject("wscript.Shell")
    
    ' Check if Office/VBA is running in 32-bit
    Dim is32bitOffice As Boolean
    #If Win64 Then
        is32bitOffice = False ' Office is 64-bit
    #Else
        is32bitOffice = True  ' Office is 32-bit
    #End If

    If architecture = "9" Then
        If is32bitOffice Then
            Shell.Run "C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -nop -noexit -c ""echo 64bit OS and 32bit Word"""
        Else
            Shell.Run "powershell.exe -nop -noexit -c ""echo 64bit OS and 64bit Word"""
        End If
    ElseIf architecture = "0" Then
        Shell.Run "powershell.exe -nop -noexit -c ""echo 32bit OS and 32bit Word"""
    End If

End Sub
