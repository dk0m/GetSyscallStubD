import std.stdio;
import core.sys.windows.windows;

extern (C) void *memcpy(void *to, const void *from, size_t numBytes);

const SYSCALL_STUB_SIZE = 23;

LPVOID readFile(LPCSTR filePath) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD fileSize = GetFileSize(hFile, NULL);

    LPVOID fileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);

     if (!ReadFile(hFile, fileData, fileSize, NULL, NULL)) {

        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, fileData);
        return NULL;

     }


    return fileData;
}

DWORD rvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (SIZE_T i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        DWORD sectionSize = sectionHeader.Misc.VirtualSize;
        DWORD sectionAddress = sectionHeader.VirtualAddress;

        if (rva >= sectionAddress && rva < sectionAddress + sectionSize) {
            return cast(DWORD)(rva - sectionAddress + sectionHeader.PointerToRawData);

        }
            
        sectionHeader = cast(PIMAGE_SECTION_HEADER)(cast(DWORD_PTR)(sectionHeader) + IMAGE_SECTION_HEADER.sizeof);
    }

    return 0;

}

T rvaToVa(T) (DWORD_PTR peBase, DWORD offset) {
    return cast(T)(peBase + offset);
}

BOOL getSyscallStub(LPCSTR targetFnName, PVOID syscallStub) {
    LPVOID ntdllBuffer = readFile("C:\\Windows\\System32\\ntdll.dll");
    DWORD_PTR peBase = cast(DWORD_PTR)ntdllBuffer;

    PIMAGE_DOS_HEADER dosHdr = cast(PIMAGE_DOS_HEADER)peBase;
    PIMAGE_NT_HEADERS ntHdrs = rvaToVa!PIMAGE_NT_HEADERS(peBase, dosHdr.e_lfanew);
    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs.OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY expDir = rvaToVa!PIMAGE_EXPORT_DIRECTORY(peBase, rvaToFileOffset(ntHdrs, optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

    PDWORD addrOfNames = rvaToVa!PDWORD(peBase, rvaToFileOffset(ntHdrs, expDir.AddressOfNames));
    PDWORD addrOfFuncs = rvaToVa!PDWORD(peBase, rvaToFileOffset(ntHdrs, expDir.AddressOfFunctions));
    PWORD addrOfOrds = rvaToVa!PWORD(peBase, rvaToFileOffset(ntHdrs, expDir.AddressOfNameOrdinals));

    for (SIZE_T i = 0; i < expDir.NumberOfFunctions; i++) {
        LPCSTR fnName = rvaToVa!LPCSTR(peBase, rvaToFileOffset(ntHdrs, addrOfNames[i]));
        WORD fnOrd = addrOfOrds[i];
        PVOID fnAddr = rvaToVa!PVOID(peBase, rvaToFileOffset(ntHdrs, addrOfFuncs[fnOrd]));

        if (!lstrcmpiA(fnName, targetFnName)) {
            memcpy(syscallStub, fnAddr, SYSCALL_STUB_SIZE);
            return TRUE;
        }
    }

    return FALSE;
}

LPVOID allocStub() {
    return VirtualAlloc(NULL, SYSCALL_STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

alias NTSTATUS = uint;

alias typeNtAllocateVirtualMemory = extern(Windows) NTSTATUS function(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

void main() {

    PVOID ntallocVmStub = allocStub();

    if (!getSyscallStub("NtAllocateVirtualMemory", ntallocVmStub)) {

        writeln("[-] Failed To Fetch Fresh Stub Of NtAllocateVirtualMemory.");
        return;

    }
    
    // Example

    typeNtAllocateVirtualMemory NtAllocateVirtualMemory = cast(typeNtAllocateVirtualMemory)ntallocVmStub;

    PVOID shellcodeBuffer;
    SIZE_T shellcodeSize = 512;

    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &shellcodeBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
         
    writefln("Shellcode Memory Allocated At: 0x%x, Status: 0x%x", shellcodeBuffer, status);

}