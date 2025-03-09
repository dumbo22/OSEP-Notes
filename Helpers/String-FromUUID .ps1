function String-FromUUID {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UUID
    )

    $guid = [Guid]::Parse($UUID)

    $byteArray = $guid.ToByteArray()

    $bytesData1 = $byteArray[0..3]
    $bytesData2 = $byteArray[4..5]
    $bytesData3 = $byteArray[6..7]
    $bytesData4 = $byteArray[8..15]

    [Array]::Reverse($bytesData1)
    [Array]::Reverse($bytesData2)
    [Array]::Reverse($bytesData3)

    $originalByteArray = $bytesData1 + $bytesData2 + $bytesData3 + $bytesData4

    $lastNonZeroIndex = ($originalByteArray.Length - 1)
    while ($lastNonZeroIndex -ge 0 -and $originalByteArray[$lastNonZeroIndex] -eq 0) {
        $lastNonZeroIndex--
    }
    if ($lastNonZeroIndex -lt 0) {
        $trimmedByteArray = @()
    } else {
        $trimmedByteArray = $originalByteArray[0..$lastNonZeroIndex]
    }

    $originalString = [System.Text.Encoding]::UTF8.GetString($trimmedByteArray)
    Write-Output $originalString
}

String-FromUUID "676f6f73-6500-0000-0000-000000000000"
String-FromUUID "646f6700-0000-0000-0000-000000000000"
