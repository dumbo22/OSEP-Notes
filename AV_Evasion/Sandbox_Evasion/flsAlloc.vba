Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long

  Dim tmp As LongPtr
  If IsNull(FlsAlloc(tmp)) Then
    Exit Function
  End If
