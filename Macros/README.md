## Notes

- Remember, Word runs under 32bit generally so be aware when compiling shellcode
- Ensure when setting up Macro's to attach the macro to the document that is being forged. Otherwise, the macro will not attach to the document
- It is more reliable to use shellcode that does not invoke a stager when running through a macro

## Resources
- https://github.com/mandiant/OfficePurge
- https://github.com/outflanknl/EvilClippy
- https://github.com/Inf0secRabbit/BadAssMacros
- https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/office-attacks/#docm-badassmacros
- https://github.com/mandiant/OfficePurge
- https://github.com/S3cur3Th1sSh1t/OffensiveVBA?tab=readme-ov-file

## VBA Stomping
⚠️ VBA stomping is not effective against Excel 97-2003 Workbook (.xls) format.
- https://github.com/mandiant/OfficePurge

  ```
    OfficePurge.exe -d word -f .\malicious.doc -m NewMacros
    OfficePurge.exe -d excel -f .\payroll.xls -m Module1
    OfficePurge.exe -d publisher -f .\donuts.pub -m ThisDocument
    OfficePurge.exe -d word -f .\malicious.doc -l
  ```

## File format
When delivering macro enabled Word documents to the target ensure the Word document is saved to the following file types:
- .doc
- .docm

For excel
- xlsm

## Auto Execute Methods 
Word

- Document_Open()
- AutoOpen()

Excel
- Workbook_Open()


## Antivrus
Macro's embedded in Word and Excel documents are subject to both on disk scanning and AMSI at macro runtime

## Sandbox Evasion

- Code snippets found in https://github.com/The-Viper-One/OSEP-Notes/tree/main/AV-Evasion/Sandbox_Evasion

## Launching x64 Processes from x86 Word and Excel
By default, `WINWORD.exe` runs as a 32-bit (x86) application. When spawning processes like `cmd` or `PowerShell` from a macro, this will also launch a 32-bit process. However, it is possible to utilize `sysnative` (a virtual directory available to 32-bit processes on 64-bit systems) to spawn a 64-bit `cmd` or `PowerShell` process.

This is especially useful when you need to launch a 64-bit Meterpreter shell.

Code examples for this can be found in the `Download_Cradles` directory.

To check whether a process is running as 32-bit or 64-bit in PowerShell, you can use the following code:

```vba
Sub CheckArchitecture()
    Dim shellCommand As String
    shellCommand = "cmd.exe /c %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -c " & _
                   Chr(34) & "if ([IntPtr]::Size -eq 8) {Write-Host '64-bit PowerShell'} else {Write-Host '32-bit PowerShell'} ; Start-Sleep -Seconds 5" & Chr(34)

    Shell shellCommand, vbNormalFocus
End Sub
```

![image](https://github.com/user-attachments/assets/886953b0-fd65-400a-bf9c-2cce302d4853)

![image](https://github.com/user-attachments/assets/5648be16-4de8-4b49-9952-c31d99527e26)



