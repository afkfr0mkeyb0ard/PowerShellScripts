param (
    [string]$Path = "Registry::HKEY_LOCAL_MACHINE",  # The registry path to start the search from (default is HKEY_LOCAL_MACHINE)
    [string]$Search = "password"  # The search term to look for in keys and values (default is "password")
)

# Get all registry keys under the specified path recursively, silently ignoring errors.
Get-ChildItem $Path -Recurse -ErrorAction SilentlyContinue |
ForEach-Object {
    $key = $_.Name  # The full registry path of the key
    $registryKey = Get-Item -LiteralPath "Registry::$key"  # Get the actual RegistryKey object
    $values = $registryKey.GetValueNames() | ForEach-Object { "$($_)=$($registryKey.GetValue($_))" }  # Get all the value names and their corresponding values
    [PSCustomObject]@{ Key = $key; Values = $values -join ", " }  # Create a custom object with the key and its values
} | Where-Object { 
    # Filter the results: Keep only keys or values that contain the search term (case-insensitive)
    $_.Key -match $Search -or $_.Values -match $Search 
}

#.\Search-Registry.ps1 -Path "Registry::HKEY_LOCAL_MACHINE\Software" -Search "password"
#.\Search-Registry.ps1 -Path "Registry::HKEY_CURRENT_USER" -Search "admin"
#.\Search-Registry.ps1 -Path "Registry::HKEY_LOCAL_MACHINE\Software" -Search "login"
