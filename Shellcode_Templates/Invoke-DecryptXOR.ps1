function Flip-Bits {
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

function Invoke-DecryptXOR {
    param (
        [byte[]]$ByteArray
    )

    # Reverse the entire byte array
    [Array]::Reverse($ByteArray)

    # Flip bits in each byte
    $bitReversedBytes = $ByteArray | ForEach-Object { Flip-Bits $_ }

    # Brute-force XOR key to find the original string
    for ($key = 0; $key -lt 256; $key++) {
        $decodedBytes = $bitReversedBytes | ForEach-Object { $_ -bxor $key }
        $decodedString = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
        
        if ($decodedString -like "*_END_*") {
            return $decodedString -replace "_END_$", ""
        }
    }

    return $null
}
