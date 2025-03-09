# Input string
$inputString = "Your long input string goes here..."

# Split the input string into chunks of maximum 100 characters each
$chunkSize = 100
$chunks = [System.Collections.ArrayList]@()
for ($i = 0; $i -lt $inputString.Length; $i += $chunkSize) {
    $chunk = $inputString.Substring($i, [Math]::Min($chunkSize, $inputString.Length - $i))
    $chunks.Add($chunk)
}

# Print the code in the specified format
for ($i = 0; $i -lt $chunks.Count; $i++) {
    Write-Output "str$i = `"$($chunks[$i])`""
}

# Construct the concatenation string dynamically
$concatenationString = "str = "
for ($i = 0; $i -lt $chunks.Count; $i++) {
    if ($i -eq 0) {
        $concatenationString += "str$i"
    } else {
        $concatenationString += " + str$i"
    }
}

# Print the dynamically constructed concatenation string
Write-Output $concatenationString
