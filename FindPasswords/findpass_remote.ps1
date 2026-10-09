# You may need to open powershell.exe using runas to authenticate
# runas /netonly /user:DOMAIN\User "powershell.exe"

# Define server IP and Share
$NetworkPath = "\\ServeurDistant\PartageSecret"

$Extensions = @("*.txt", "*.xml", "*.ini", "*.env", "*.conf", "*.bat", "*.cmd", "*.ps1")
$Motifs = @("DefaultPassword", "cpassword", "SecureString", "(pass|password|passw)\s*[:=]", "-p\s+\S+")

Get-ChildItem -Path $NetworkPath -Recurse -File -Include $Extensions -ErrorAction SilentlyContinue | Select-String -Pattern $Motifs -ErrorAction SilentlyContinue | Select-Object Path, LineNumber, Line
