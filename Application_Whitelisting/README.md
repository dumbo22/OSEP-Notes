## Resources

- https://github.com/api0cradle/UltimateAppLockerByPassList/tree/master
- https://github.com/api0cradle/PowerAL
- https://lolbas-project.github.io/
- https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/
  
## Default Applocker
Default applocker rules tend to block the following

- **Executable files**: `.exe`, `.com`
- **Windows Installer files**: `.msi`, `.msp`
- **Scripts**: `.js`, `.ps1`, `.vbs`, `.cmd`, `.bat`
- **Packaged apps**: `.aappx`

 💡 AppLocker rules do not apply to the built-in local accounts such as Local System, Local Service, or Network Service. Neither do they apply to the IIS DefaultAppPool
## Emumerating AppLocker rules
PowerShell can be used to enumerate effective AppLocker rules in place
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-AppLockerPolicy -Effective -xml | Out-file AppLockerRules.xml ; .\AppLockerRules.xml
```
## Testing Applocker Rules
```powershell
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Alpha\AMSI.ps1" -User alpha
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Alpha\AES_Shellcode_Runner.exe" -User alpha
```
```
PS C:\Users\alpha>  Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Alpha\AMSI.ps1" -User alpha

FilePath          PolicyDecision MatchingRule
--------          -------------- ------------
C:\Alpha\AMSI.ps1        Allowed All scripts


PS C:\Users\alpha>  Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Alpha\AES_Shellcode_Runner.exe" -User alpha

FilePath                           PolicyDecision MatchingRule
--------                           -------------- ------------
C:\Alpha\AES_Shellcode_Runner.exe DeniedByDefault
```


## Using Accesschk.exe to identify paths of interest
```batch
:: Check if the current user is a member of any specific non-default groups
net user %USERNAME%

:: Check permissions for a specific group
accesschk -nobanner -w -s -u "SPECIFIC_GROUP" "C:\Program Files"
accesschk -nobanner -w -s -u "SPECIFIC_GROUP" "C:\Program Files (x86)"
accesschk -nobanner -w -s -u "SPECIFIC_GROUP" "C:\Windows"

:: Check permissions for the current user
accesschk -nobanner -w -s -u "%USERNAME%" "C:\Program Files"
accesschk -nobanner -w -s -u "%USERNAME%" "C:\Program Files (x86)"
accesschk -nobanner -w -s -u "%USERNAME%" "C:\Windows"

:: Check permissions for common groups
:: Program Files
accesschk -nobanner -w -s -u "Users" "C:\Program Files"
accesschk -nobanner -w -s -u "Everyone" "C:\Program Files"
accesschk -nobanner -w -s -u "Authenticated Users" "C:\Program Files"
accesschk -nobanner -w -s -u "Interactive" "C:\Program Files"

:: Program Files (x86)
accesschk -nobanner -w -s -u "Users" "C:\Program Files (x86)"
accesschk -nobanner -w -s -u "Everyone" "C:\Program Files (x86)"
accesschk -nobanner -w -s -u "Authenticated Users" "C:\Program Files (x86)"
accesschk -nobanner -w -s -u "Interactive" "C:\Program Files (x86)"

:: Windows directory
accesschk -nobanner -w -s -u "Users" "C:\Windows"
accesschk -nobanner -w -s -u "Everyone" "C:\Windows"
accesschk -nobanner -w -s -u "Authenticated Users" "C:\Windows"
accesschk -nobanner -w -s -u "Interactive" "C:\Windows"
```
## Using PowerShell to identify paths of interest
```powershell
function Find-AppLockerBypass {
    $ErrorActionPreference = "SilentlyContinue"
    $userChecks = @(
        "NT AUTHORITY\Authenticated Users",
        "BUILTIN\Users",
        "Everyone",
        $env:USERNAME,
        "NT AUTHORITY\INTERACTIVE"
    )

    $directoriesToCheck = @(
        $env:windir,
        "C:\Program Files",
        "C:\Program Files (x86)"
    )

    foreach ($directoryPath in $directoriesToCheck) {
        Get-ChildItem -Path $directoryPath -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $directory = $_
            $acl = Get-Acl -Path $directory.FullName

            $acl.Access | Where-Object {
                $_.AccessControlType -eq "Allow" -and
                $_.IdentityReference.Value -in $userChecks -and
                ($_.FileSystemRights -match "Write|Create") -and
                $_.FileSystemRights -match "Execute"
            } | ForEach-Object {
                Write-Host "$($directory.FullName): $($_.IdentityReference.Value) ($($_.FileSystemRights))"
            }
        }
    }
}

Find-AppLockerBypass
```

## Default world writeable folders by all users

```
C:\Windows\Registration\CRMLog
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\com\dmp
C:\Windows\System32\FxsTmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\System32\com\dmp
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\Windows\Temp
C:\windows\tracing
```

# Understanding icacls Permission Flags for AppLocker Bypasses

When analyzing file and folder permissions to find potential ways to bypass AppLocker, it helps to understand the permission flags used by `icacls`. Below are some examples of common flags and potential abuse vectors.
## Basic Permissions:

- **F** (Full Control): The user can do anything, including changing permissions, modifying files, or deleting them.
- **M** (Modify): Allows users to read, write, execute, and delete files, but not change permissions.
- **RX** (Read and Execute): Users can read the file or folder and run it, but can’t make changes. This is important for AppLocker bypasses since you need the ability to execute files without needing modification rights.
- **R** (Read): The user can read the contents, but can’t change or execute anything.
- **W** (Write): The user can add or modify files but not delete or execute them.

## Inheritance Flags:

- **OI** (Object Inherit): Permissions are passed down to files within the folder.
- **CI** (Container Inherit): Permissions are inherited by subdirectories.
- **IO** (Inherit Only): The permission doesn’t apply to the parent folder itself, only to the child objects (files or subdirectories).
- **NP** (No Propagate Inherit): Prevents the permissions from being passed down to further subfolders or files.

## Examples of Permission Configurations:

### 1. **BUILTIN\Users:(RX)**  
   This means the **Users** group has permission to read and execute the file or folder, but can’t make changes. If you find a folder like this, you might be able to run certain files despite AppLocker restrictions.

### 2. **BUILTIN\Users:(OI)(CI)(RX)**  
   In this case, **Users** can read and execute all files and folders within the specified directory. The (OI) and (CI) flags ensure that these permissions apply to everything inside the folder, making it an ideal place to look for executables that might allow a bypass.

### 3. **NT AUTHORITY\SYSTEM:(OI)(CI)(RX)**  
   The **SYSTEM** account can read and execute all files and directories within the folder. While this permission setup is common for system-critical directories, it may offer opportunities if you're looking for files to execute as part of a bypass.

### 4. **CREATOR OWNER:(OI)(CI)(IO)(RX)**  
   The **CREATOR OWNER** (the person who created the file or folder) has read and execute rights, but only on child files or folders (thanks to the **IO** flag). This can be useful if AppLocker blocks access at the parent level but leaves child items executable.

### 5. **BUILTIN\Users:(OI)(CI)(IO)(RX)**  
   **Users** have read and execute permissions on all child objects, but the permission doesn't apply to the parent directory itself. This means you might be able to execute files within subdirectories, even if the parent folder doesn’t allow it.

### 6. **Everyone:(RX)**  
   When **Everyone** has read and execute permissions on a file or folder, any user can run it. This can be a significant point of interest for AppLocker bypass attempts, as any executable in such a folder is fair game for execution by any user.

### 7. **Authenticated Users:(OI)(CI)(RX)**  
   **Authenticated Users** (any user logged in with valid credentials) can read and execute files and subfolders in this directory. Again, this could be a prime target for finding executable files that are allowed by AppLocker but still accessible.

## AppLocker Bypass Tips:

- **RX (Read and Execute)** permissions are key to most bypass strategies, as they allow you to run files without needing to modify them. Always look for folders where users have RX access, even if they don't have write or modify rights.
  
- **Inherited RX permissions** (signified by the **OI**, **CI**, and **IO** flags) are also important. Even if the top-level directory doesn’t allow execution, inherited permissions on subfolders or files could open up opportunities for bypasses.

- Folders where **Everyone** or **Authenticated Users** have **RX** permissions are especially valuable, as they allow any user to execute files, which can be an easy way to bypass AppLocker if the right executables are present.

- **Full Control (F)** for non-admin users is particularly risky, as users can modify and run files freely, offering many ways to bypass AppLocker restrictions.

## Practical Example

In the output below the default folder c:\windows\tasks has the following icacls.exe output.

```
c:\Tools\SysinternalsSuite>icacls.exe C:\Windows\Tasks
C:\Windows\Tasks NT AUTHORITY\Authenticated Users:(RX,WD)
                 BUILTIN\Administrators:(F)
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(F)
                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                 CREATOR OWNER:(OI)(CI)(IO)(F)
```


The group **"Authenticated Users"** has the flags **(RX, WD)** on the folder `C:\Windows\Tasks`.

- **(RX, WD)**: These are the permissions granted to the **Authenticated Users** group:
  
  - **RX**: Read and Execute. This means the group can read the contents of files and directories and execute files (e.g., `.exe` or `.bat` files).
  
  - **WD**: Write Data. This permission allows the group to add or modify data. Specifically:
  
    - On **files**: It allows writing or modifying the content of the file.
    - On **directories**: It allows creating new files within the directory.

Practically, this means anyone on the system can bypass the AppLocker rules by placing an executable or script into this folder and executing. For example, with default applocker rules in place, attempting to launch calc.exe in a users folder blocks execution as shown

![image](https://github.com/user-attachments/assets/82fe7fda-f480-471d-81d5-70276efc935e)


Placing the calc.exe file into c:\windows\tasks by comparison allows execution:

![image](https://github.com/user-attachments/assets/f6c447eb-7f36-4af2-b996-05806416d112)

