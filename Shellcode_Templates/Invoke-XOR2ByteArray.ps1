function Reverse-ByteBits {
    param (
        [byte]$byte
    )
    
    $reversedByte = 0
    for ($i = 0; $i -lt 8; $i++) {
        $reversedByte = ($reversedByte -shl 1) -bor ($byte -band 1)
        $byte = $byte -shr 1
    }
    return $reversedByte
}

function Invoke-XOR2ByteArray {
    param (
        [string]$InputStrings
    )

    # Split the input string by commas to handle multiple inputs
    $InputStringArray = $InputStrings -split ','

    foreach ($InputString in $InputStringArray) {
        $InputString = $InputString.Trim()

        # Append a delimiter to the input string
        $InputStringWithDelimiter = $InputString + "_END_"
        $byteArray = [System.Text.Encoding]::UTF8.GetBytes($InputStringWithDelimiter)

        # Generate a random XOR key
        $random = New-Object System.Random
        $key = $random.Next(0, 256)

        # Perform XOR encryption
        $encodedBytes = $byteArray | ForEach-Object { $_ -bxor $key }

        # Reverse the bits in each byte
        $reversedBitsBytes = $encodedBytes | ForEach-Object { Reverse-ByteBits $_ }

        # Reverse the entire byte array
        [Array]::Reverse($reversedBitsBytes)

        # Convert encrypted bytes to hex format
        $hexArray = $reversedBitsBytes | ForEach-Object { "0x{0:X2}" -f $_ }

        # Create variable names based on input string, replace spaces and dots with underscores
        $variableName = $InputString -replace ' ', '_' -replace '\.', '_'

        # Generate output for encryption
        Write-Host "`n[Byte[]] `$d${variableName}_Bytes = " + ($hexArray -join ', ')
        Write-Host "[string] `$d${variableName} = Retrieve-Data -ByteArray `$d${variableName}_Bytes"
    }
}
