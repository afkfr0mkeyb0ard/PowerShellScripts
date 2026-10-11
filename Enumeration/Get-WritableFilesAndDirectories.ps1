function Get-AllFiles {
    param (
        [string]$Path
    )

    $allFiles = @()

    if ($Path) {
        Write-Host "Scanning $Path ..."
        try {
            $allFiles += Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty FullName
        } catch {
            Write-Warning "Error accessing ${Path}: $_"
        }
    } else {
        $drives = (Get-PSDrive -PSProvider FileSystem).Name
        foreach ($drive in $drives) {
            $drivePath = "$drive`:\"
            Write-Host "Scanning $drivePath ..."
            try {
                $allFiles += Get-ChildItem -Path $drivePath -Recurse -File -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty FullName
            } catch {
                Write-Warning "Error accessing ${drivePath}: $_"
            }
        }
    }

    return $allFiles
}

function Test-FileAccess {
    param (
        [Parameter(Mandatory)]
        [string[]]$FilePaths,

        [Parameter(Mandatory)]
        [ValidateSet("R", "W", "E")]
        [string[]]$Permission
    )

    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($user)

    $results = foreach ($file in $FilePaths) {
        # Initial properties with default values
        $props = @{ Path = $file }

        # Handle 'R' (Read) permission
        if ("R" -in $Permission) {
            $props["Readable"] = $false
            try {
                $acl = Get-Acl -Path $file
                $rules = $acl.Access
                foreach ($rule in $rules) {
                    if ($principal.IsInRole($rule.IdentityReference)) {
                        if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) {
                            if ($rule.AccessControlType -eq "Allow") { $props["Readable"] = $true }
                            if ($rule.AccessControlType -eq "Deny")  { $props["Readable"] = $false }
                        }
                    }
                }
            } catch {
                #Write-Warning "Cannot check Read access for $file : $_"
            }
        }

        # Handle 'W' (Write) permission
        if ("W" -in $Permission) {
            $props["Writable"] = $false
            try {
                $stream = [System.IO.File]::Open($file, 'Open', 'Write')
                $stream.Close()
                $props["Writable"] = $true
            } catch {
                $props["Writable"] = $false
            }
        }

        # Handle 'E' (Execute) permission
        if ("E" -in $Permission) {
            $props["Executable"] = $false
            try {
                $acl = Get-Acl -Path $file
                $rules = $acl.Access
                foreach ($rule in $rules) {
                    if ($principal.IsInRole($rule.IdentityReference)) {
                        if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) {
                            if ($rule.AccessControlType -eq "Allow") { $props["Executable"] = $true }
                            if ($rule.AccessControlType -eq "Deny")  { $props["Executable"] = $false }
                        }
                    }
                }
            } catch {
                #Write-Warning "Cannot check Execute access for $file : $_"
            }
        }

        # Check if at least one permission is true
        $hasPermission = $Permission | ForEach-Object {
            switch ($_){
                "R" { $props["Readable"] }
                "W" { $props["Writable"] }
                "E" { $props["Executable"] }
            }
        } | Where-Object { $_ -eq $true }

        if ($hasPermission) {
            # Return the result with explicit column order
            [PSCustomObject]@{
                Path       = $props["Path"]
                Readable   = $props["Readable"]
                Writable   = $props["Writable"]
                Executable = $props["Executable"]
            }
        }
    }

    return $results
}

function Test-FileWritable {
    param (
        [Parameter(Mandatory)]
        [string[]]$FilePaths
    )

    foreach ($file in $FilePaths) {
        $writable = $false

        try {
            $stream = [System.IO.File]::Open($file, 'Open', 'Write')
            $stream.Close()
            $writable = $true
        } catch {
            $writable = $false
        }

        [PSCustomObject]@{
            Path     = $file
            Writable = $writable
        }
    }
}

function Test-FileReadable {
    param (
        [Parameter(Mandatory)]
        [string[]]$FilePaths
    )

    foreach ($file in $FilePaths) {
        $readable = $false

        try {
            $acl = Get-Acl -Path $file
            $rules = $acl.Access
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($user)

            foreach ($rule in $rules) {
                if ($principal.IsInRole($rule.IdentityReference)) {
                    if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) {
                        if ($rule.AccessControlType -eq "Allow") { $readable = $true }
                        if ($rule.AccessControlType -eq "Deny")  { $readable = $false }
                    }
                }
            }
        } catch {
            #Write-Warning "Cannot check READ access for $file : $_"
        }

        [PSCustomObject]@{
            Path    = $file
            Readable = $readable
        }
    }
}

function Test-FileExecutable {
    param (
        [Parameter(Mandatory)]
        [string[]]$FilePaths
    )

    foreach ($file in $FilePaths) {
        $executable = $false

        try {
            $acl = Get-Acl -Path $file
            $rules = $acl.Access
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($user)

            foreach ($rule in $rules) {
                if ($principal.IsInRole($rule.IdentityReference)) {
                    if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) {
                        if ($rule.AccessControlType -eq "Allow") { $executable = $true }
                        if ($rule.AccessControlType -eq "Deny")  { $executable = $false }
                    }
                }
            }
        } catch {
            #Write-Warning "Cannot check EXECUTE access for $file : $_"
        }

        [PSCustomObject]@{
            Path       = $file
            Executable = $executable
        }
    }
}

# Function to check if the current user has write permission on a given directory
function Test-FolderWritePermission {
    param (
        [string]$DirectoryPath
    )
    $writeAccess = $false
    $filepath = Join-Path $DirectoryPath "poc.txt"
    try {
        echo "Poc" | Out-File $filepath
	$writeAccess = $true
	
    } catch {}

	if ($writeAccess){
	try{Remove-Item $filepath -ErrorAction Stop}
	catch{Write-Host "[!] Cannot remove file $filepath"}}
    return $writeAccess
}

# Function to get all directories recursively and check for write access
function Get-WritableDirectories {
    param (
        [string]$RootPath
    )
    $directories = Get-ChildItem $RootPath -Force -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | Where { $_.StartsWith("C:\")}
    foreach ($dir in $directories) {
        if (Test-FolderWritePermission -DirectoryPath $dir) {
            Write-Host $dir
        }
    }
}

# Check for writable files only
# Test-FileAccess -FilePaths (Get-AllFiles -Path "C:\Windows\System32") -Permission W | Format-Table -AutoSize

# Check for writable and executable files 
# Test-FileAccess -FilePaths (Get-AllFiles -Path "C:\Windows\System32") -Permission W,E | Format-Table -AutoSize

# Check for readable, writable and executable files 
# Test-FileAccess -FilePaths (Get-AllFiles -Path "C:\Windows\System32") -Permission R,W,E | Format-Table -AutoSize

# Check for writable folders
# Get-WritableDirectories -RootPath "C:\Windows\"

# Load from internet
# powershell -ep bypass -nop -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/afkfr0mkeyb0ard/Get-WritableDirectories/refs/heads/main/functions.ps1');
