Function GenerateGlobalKeys {
    param ([switch]$csharp)
    
    # Generate AES Key and IV once and store them globally
    $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
    [string] $GlobalKey = [System.Convert]::ToBase64String($AES.Key)
    [string] $GlobalIV = [System.Convert]::ToBase64String($AES.IV)
    Write-Host ""
    Write-Host ""
    # Print the global Key and IV at the top of the output
    if (-not ($Bytes)) {
        if (-not($csharp)){
            Write-Host "`n// Store the Global Key and IV at the top of the output"
            Write-Host "`nstatic string GlobalKey = `"$GlobalKey`";"
            Write-Host "static string GlobalIV = `"$GlobalIV`";"
            Write-Host "`n"
        }
        else {
            Write-Host "`n# Store the Global Key and IV at the top of the output"
            Write-Host "[string] `$GlobalKey = '$GlobalKey'"
            Write-Host "[string] `$GlobalIV = '$GlobalIV'`n"
        }
    }

    # Return the generated Key and IV for use in encryption
    return @{ Key = $GlobalKey; IV = $GlobalIV; AES = $AES }
}

function Invoke-EncryptAES {
    param (
        [Parameter(Mandatory = $false)]
        [string]$InputStrings,
        [Parameter(Mandatory = $false)]
        [byte[]]$Bytes,
        [switch]$MultipleKeys,
        [switch]$csharp  # New switch parameter for C# output format
    )

    # Generate or use global keys
    if (-not $MultipleKeys) {
        if (-not ($csharp)){
        $globalKeys = GenerateGlobalKeys -csharp
        
        }

        else {
        $globalKeys = GenerateGlobalKeys

        }
        
        $GlobalKey = $globalKeys['Key']
        $GlobalIV = $globalKeys['IV']
        $AES = $globalKeys['AES']  # Store the AES object for reuse
    }

    # Check if -Bytes is specified
    if ($Bytes) {
        # Encrypting a byte array
        $InputBytes = $Bytes

        # Generate individual keys if $MultipleKeys switch is set
        if ($MultipleKeys) {
            $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
            $Key = $AES.Key
            $IV = $AES.IV
            [string]$KeyBase64 = [System.Convert]::ToBase64String($Key)
            [string]$IVBase64 = [System.Convert]::ToBase64String($IV)
        }
        else {
            # Use the global Key and IV
            $Key = [System.Convert]::FromBase64String($GlobalKey)
            $IV = [System.Convert]::FromBase64String($GlobalIV)
            $KeyBase64 = $GlobalKey
            $IVBase64 = $GlobalIV
        }

        # Reset AES object with the appropriate key and IV
        $AES.Key = $Key
        $AES.IV = $IV

        # Create AES encryptor
        $encryptor = $AES.CreateEncryptor()
        $memoryStream = New-Object -TypeName IO.MemoryStream
        $cryptoStream = New-Object -TypeName Security.Cryptography.CryptoStream -ArgumentList @( $memoryStream, $encryptor, 'Write' )

        # Encrypt the byte array
        $cryptoStream.Write($InputBytes, 0, $InputBytes.Length)
        $cryptoStream.FlushFinalBlock()
        $encryptedBytes = $memoryStream.ToArray()

        $cryptoStream.Close()
        $memoryStream.Close()

        # Convert encrypted bytes to hex format
        $hexArray = $encryptedBytes | ForEach-Object { "0x{0:X2}" -f $_ }
        $byteCount = $hexArray.Length

        if ($csharp) {
            # Output in C# format with byte count
            $output = @"
byte[] Warhead_Bytes = new byte[$byteCount] { $(($hexArray -join ', ')) };
byte[] Warhead = DecryptAESAsBytes(Warhead_Bytes, `"$KeyBase64`", `"$IVBase64`");
"@
        } else {
            # Output in PowerShell format
            $output = @"
[Byte[]] `$Warhead_Bytes = $(($hexArray -join ', '))
[Byte[]] `$Warhead = Invoke-DecryptAES -Data `$Warhead_Bytes -KeyBase64 '$KeyBase64' -IVBase64 '$IVBase64' -Bytes
"@
        }

        # Write output to file
        $outputFile = Join-Path -Path $PWD -ChildPath "encrypted_output.txt"
        $output | Out-File -FilePath $outputFile -Encoding utf8

        # Open the file in Notepad
        Start-Process notepad.exe -ArgumentList $outputFile
    } 
    elseif ($InputStrings) {
        # Encrypting strings
        $InputStringArray = $InputStrings -split ','

        foreach ($InputString in $InputStringArray) {
            $InputString = $InputString.Trim()

            # Convert input string to byte array (Removed "_END_" delimiter)
            $InputBytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)

            # Use individual keys if $MultipleKeys switch is set
            if ($MultipleKeys) {
                $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
                $Key = $AES.Key
                $IV = $AES.IV
                [string]$KeyBase64 = [System.Convert]::ToBase64String($Key)
                [string]$IVBase64 = [System.Convert]::ToBase64String($IV)
            }
            else {
                # Use the global Key and IV
                $Key = [System.Convert]::FromBase64String($GlobalKey)
                $IV = [System.Convert]::FromBase64String($GlobalIV)
                $KeyBase64 = $GlobalKey
                $IVBase64 = $GlobalIV
            }

            # Ensure the AES object is not null
            if (-not $AES) {
                $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
            }

            # Reset AES object with the appropriate key and IV
            $AES.Key = $Key
            $AES.IV = $IV

            # Create AES encryptor
            $encryptor = $AES.CreateEncryptor()
            $memoryStream = New-Object -TypeName IO.MemoryStream
            $cryptoStream = New-Object -TypeName Security.Cryptography.CryptoStream -ArgumentList @( $memoryStream, $encryptor, 'Write' )

            # Encrypt the byte array
            $cryptoStream.Write($InputBytes, 0, $InputBytes.Length)
            $cryptoStream.FlushFinalBlock()
            $encryptedBytes = $memoryStream.ToArray()

            $cryptoStream.Close()
            $memoryStream.Close()

            # Convert encrypted bytes to hex format
            $hexArray = $encryptedBytes | ForEach-Object { "0x{0:X2}" -f $_ }
            $byteCount = $hexArray.Length

            # Create variable names based on input string, replace spaces and dots with underscores
            $variableName = $InputString -replace ' ', '_' -replace '\.', '_'

            if ($csharp) {
                # Output in C# format with byte count
                Write-Host "`nstatic byte[] d${variableName}_Bytes = new byte[$byteCount] { "($hexArray -join ', ')" };"
                if ($MultipleKeys) {
                    #Write-Host "string d${variableName}_Key = `"$KeyBase64`";"
                    #Write-Host "string d${variableName}_IV = `"$IVBase64`";"
                    Write-Host "static string d${variableName} = DecryptAESAsString(d${variableName}_Bytes, `"$KeyBase64`", `"$IVBase64`");"
                }
                else {
                    Write-Host "static string d${variableName} = DecryptAESAsString(d${variableName}_Bytes, GlobalKey, GlobalIV);"
                }
            } else {
                # Output in PowerShell format
                Write-Host "`n[Byte[]] `$d${variableName}_Bytes = " + ($hexArray -join ', ')
                if ($MultipleKeys) {
                    #Write-Host "[string] `$d${variableName}_Key = '$KeyBase64'"
                    #Write-Host "[string] `$d${variableName}_IV = '$IVBase64'"
                    Write-Host "[string] `$d${variableName} = Invoke-DecryptAES -Data `$d${variableName}_Bytes -KeyBase64 `"$KeyBase64`" -IVBase64 `"$IVBase64`""
                }
                else {
                    Write-Host "[string] `$d${variableName} = Invoke-DecryptAES -Data `$d${variableName}_Bytes -KeyBase64 `$GlobalKey -IVBase64 `$GlobalIV"
                }
            }
        }
    }
    else {
        Write-Host "Please provide either -InputStrings or -Bytes."
    }
}
