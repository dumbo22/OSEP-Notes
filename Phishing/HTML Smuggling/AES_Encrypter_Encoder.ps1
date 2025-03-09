function CreateAES {
    param (
        [byte[]]$File,
        [byte[]]$Key,
        [byte[]]$IV
    )
    
    $AES = [Security.Cryptography.SymmetricAlgorithm]::Create('AES')
    $AES.Key = $Key
    $AES.IV = $IV
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $encryptor = $AES.CreateEncryptor($AES.Key, $AES.IV)
    $memoryStream = New-Object -TypeName IO.MemoryStream
    $cryptoStream = New-Object -TypeName Security.Cryptography.CryptoStream -ArgumentList @( $memoryStream, $encryptor, 'Write' )
    
    $cryptoStream.Write($File, 0, $File.Length)
    $cryptoStream.FlushFinalBlock()
    $encryptedBytes = $memoryStream.ToArray()
    
    $cryptoStream.Close()
    $memoryStream.Close()
    
    return $encryptedBytes
}

$FilePath = "C:\Users\Administrator\source\repos\Standard_Shellcode_Runner_Dynamic_Invoke\bin\x64\Release\Standard_Shellcode_Runner_Dynamic_Invoke.exe"
$FileBytes = [System.IO.File]::ReadAllBytes($FilePath)

$AES = [Security.Cryptography.Aes]::Create()
$AES.KeySize = 256
$AES.GenerateKey()
$AES.GenerateIV()
$Key = $AES.Key
$IV = $AES.IV

$Encrypted = CreateAES -File $FileBytes -Key $Key -IV $IV

[string]$KeyBase64 = [System.Convert]::ToBase64String($Key)
[string]$IVBase64 = [System.Convert]::ToBase64String($IV)
[string]$EncryptedBase64 = [System.Convert]::ToBase64String($Encrypted)

Write-Output "[+] Key (Base64)     :  $KeyBase64"
Write-Output "[+] IV (Base64)      :  $IVBase64"
Write-Output "[+] Encrypted payload copied to clipboard."
$EncryptedBase64 | Set-Clipboard
