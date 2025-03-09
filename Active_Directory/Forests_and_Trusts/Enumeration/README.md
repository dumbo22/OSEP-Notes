# Forest and trust enumeration

## nltest
```powershell
# List Trusted Domains
nltest /domain_trusts

# Get Domain Controller for a Domain
nltest /dsgetdc:<DomainName>

# List All Domain Controllers in a Domain
nltest /dclist:<DomainName>

# Get Parent Domain of the Current Domain
nltest /parentdomain

# Get DNS Names for a Domain Controller
nltest /dsgetdc:<DomainName> /dns
```
## Native
```powershell
Function Get-TrustRelationships {
    $output = @()

    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $currentForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

    $output += "Current Domain: $($currentDomain.Name)"
    $output += "Current Forest: $($currentForest.Name)"
    $output += "====================================="

    $domainTrusts = $currentDomain.GetAllTrustRelationships()
    if ($domainTrusts.Count -gt 0) {
        $output += "`nDomain Trust Relationships:"
        foreach ($trust in $domainTrusts) {
            $output += "Source Domain    : $($trust.SourceName)"
            $output += "Target Domain    : $($trust.TargetName)"
            $output += "Trust Type       : $($trust.TrustType)"
            $output += "Trust Direction  : $($trust.TrustDirection)"
            $output += "----------------------------------------"
        }
    } else {
        $output += "No domain trust relationships found."
    }

    $forestTrusts = $currentForest.GetAllTrustRelationships()
    if ($forestTrusts.Count -gt 0) {
        $output += "`nForest Trust Relationships:"
        foreach ($trust in $forestTrusts) {
            $output += "Source Forest    : $($trust.SourceName)"
            $output += "Target Forest    : $($trust.TargetName)"
            $output += "Trust Type       : $($trust.TrustType)"
            $output += "Trust Direction  : $($trust.TrustDirection)"
            $output += "----------------------------------------"
        }
    } else {
        $output += "No forest trust relationships found."
    }

    return $output
}

$result = Get-TrustRelationships
$result
```
## Powerview
```powershell
# Enumerate all Domains in the forest
Get-NetForestDomain

# Get all Domains in Forest then list each Domain trust
Get-NetForestDomain -Verbose | Get-DomainTrust

# Map all reachable Domain trusts
Get-DomainTrustMapping
Get-DomainTrustMapping | Select SourceName,TargetName,TrustType,TrustDirection

# List external trusts
Get-NetForestDomain -Verbose | Get-DomainTrust |?{$_.TrustType -eq 'External'}

# Enumerate trusts across the domain
Get-DomainTrust

# Find users in the current Domain that reside in Groups across trusts
Find-ForeignUser
```
