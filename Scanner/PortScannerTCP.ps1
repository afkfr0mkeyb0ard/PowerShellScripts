$target = "192.168.1.1"
$ports = @(21,22,23,25,53,80,81,88,111,135,139,143,161,389,443,445,636,995,1352,1433,1521,1522,1723,2049,2301,2381,3128,3260,3268,3306,3389,3999,4848,5000,5005,5432,5601,5666,5800,5900,5901,5985,5986,6000,7001,7002,8000,8080,8081,8082,8100,8443,8453,8787,8788,8888,9001,9200,9443,9875,9999,10000,18000,27017,28038,30024,50000)

$minDelay = 30
$maxDelay = 50

foreach ($port in $ports) {
$result = Test-NetConnection -ComputerName $target -Port $port
if ($result.TcpTestSucceeded) {
Write-Host "Port $port on $target is OPEN."
} else {
Write-Host "Port $port on $target is CLOSED."
}
$randomDelay = Get-Random -Minimum $minDelay -Maximum $maxDelay
Start-Sleep -Seconds $randomDelay
}
