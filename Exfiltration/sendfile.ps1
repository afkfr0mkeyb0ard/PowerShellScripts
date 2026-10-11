# To receive the file server-side:
# nc -lv 80 > received_file.bin

# To send the file:
# PS> .\sendfile.ps1 -file "example.exe" -dest "192.168.0.2:80"

param (
    [Parameter(Mandatory=$true)]
    [string]$file,

    [Parameter(Mandatory=$true)]
    [string]$dest
)

# Parse IP:port
$ip, $port = $dest.Split(':')
$port = [int]$port

# Check if file exists
if (-not (Test-Path $file)) {
    Write-Error "File '$file' does not exist."
    exit 1
}

# Send file via TCP
try {
    Write-Host "Connecting to ${ip}:$port..."
    $socket = New-Object System.Net.Sockets.TcpClient($ip, $port)
    $stream = $socket.GetStream()
    $fileStream = [System.IO.File]::OpenRead($file)
    Write-Host "Sending file '$file'..."
    $fileStream.CopyTo($stream)
    Write-Host "File sent successfully!"
}
catch {
    Write-Error "Error while sending: $_"
}
finally {
    if ($stream) { $stream.Close() }
    if ($socket) { $socket.Close() }
    if ($fileStream) { $fileStream.Close() }
}
