
function Invoke-DecryptAES {
    param (
        [byte[]]$Data,
        [string]$KeyBase64,
        [string]$IVBase64,
        [switch]$Bytes
    )

    # Convert the Base64 strings to byte arrays for the Key and IV
    $Key = [System.Convert]::FromBase64String($KeyBase64)
    $IV = [System.Convert]::FromBase64String($IVBase64)

    # Initialize the AES algorithm
    $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
    $AES.Key = $Key
    $AES.IV = $IV

    # Create decryptor and memory stream
    $decryptor = $AES.CreateDecryptor($AES.Key, $AES.IV)
    $memoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList (,$Data)
    $cryptoStream = New-Object -TypeName Security.Cryptography.CryptoStream -ArgumentList @($memoryStream, $decryptor, 'Read')

    # Create a byte array to store decrypted data
    $decryptedBytes = New-Object -TypeName Byte[] -ArgumentList $Data.Length
    $decryptedByteCount = $cryptoStream.Read($decryptedBytes, 0, $decryptedBytes.Length)
    
    # Close the streams
    $cryptoStream.Close()
    $memoryStream.Close()

    # Check if the output should be a byte array
    if ($Bytes) {
        # Return the byte array directly
        return $decryptedBytes[0..($decryptedByteCount - 1)]
    } else {
        # Convert to string if -Bytes is not specified
        $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes[0..($decryptedByteCount - 1)])

        # Remove the delimiter "_END_" if it exists
        if ($decryptedString -like "*_END_*") {
            $decryptedString = $decryptedString -replace "_END_$", ""
        }

        return $decryptedString
    }
}
