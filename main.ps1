$notepad = Start-Process notepad -PassThru
Start-Sleep -Seconds 1

$kernel32 = Add-Type -Name "Kernel32" -Namespace Win32 -PassThru -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
"@

$user32 = Add-Type -Name "User32" -Namespace Win32 -PassThru -MemberDefinition @"
[DllImport("user32.dll", SetLastError=true)]
public static extern int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);
"@

$PROCESS_ALL_ACCESS = 0x1F0FFF
$hProcess = $kernel32::OpenProcess($PROCESS_ALL_ACCESS, $false, $notepad.Id)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "Failed to open Notepad process"
    exit
}

$hUser32 = $kernel32::GetModuleHandle("user32.dll")
$MessageBoxAddr = $kernel32::GetProcAddress($hUser32, "MessageBoxA")

if ($MessageBoxAddr -eq [IntPtr]::Zero) {
    Write-Host "Failed to get address of MessageBoxA"
    exit
}

$message = [System.Text.Encoding]::ASCII.GetBytes("Hello World" + [char]0)
$size = $message.Length
$MEM_COMMIT = 0x1000
$PAGE_READWRITE = 0x04
$allocatedMemory = $kernel32::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$size, $MEM_COMMIT, $PAGE_READWRITE)

if ($allocatedMemory -eq [IntPtr]::Zero) {
    Write-Host "Memory allocation failed"
    exit
}

[UIntPtr]$bytesWritten = [UIntPtr]::Zero
$writeSuccess = $kernel32::WriteProcessMemory($hProcess, $allocatedMemory, $message, [uint32]$size, [ref]$bytesWritten)

if (-not $writeSuccess) {
    Write-Host "Failed to write message to process memory"
    exit
}

$threadHandle = $kernel32::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $MessageBoxAddr, $allocatedMemory, 0, [IntPtr]::Zero)

if ($threadHandle -eq [IntPtr]::Zero) {
    Write-Host "Failed to create remote thread"
} else {
    Write-Host "Injection successful! MessageBox should appear in Notepad."
}
