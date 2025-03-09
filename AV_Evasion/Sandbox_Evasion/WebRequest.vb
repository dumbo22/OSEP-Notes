Sub WebRequest()
    Dim httpRequest As Object
    Dim statusCode As Integer
    
    On Error Resume Next
    Set httpRequest = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    httpRequest.Open "GET", "http://NotARealDomainPLS/default.html", False
    httpRequest.Send
    statusCode = httpRequest.Status
    
    If statusCode = 200 Then
        End
    End If
    
    On Error GoTo 0
End Sub

