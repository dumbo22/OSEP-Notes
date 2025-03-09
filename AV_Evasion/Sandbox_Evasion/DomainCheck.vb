Sub DomainCheck()
    On Error Resume Next
    Set objRootDSE = GetObject("LDAP://RootDSE")
    
    If Err.Number <> 0 Then
        WScript.Quit
    End If
    
    On Error GoTo 0
End Sub
