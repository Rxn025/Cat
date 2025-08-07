// rd.cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <fstream>
#include <wintrust.h>
#include <Softpub.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")

using namespace std;

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

struct SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2[2];
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T VirtualMemorySize;
    SIZE_T PeakVirtualMemorySize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved4;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved5;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
};

bool verifyFileSignature(const wstring& filePath) {
    LONG status;
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO), nullptr, filePath.c_str(), nullptr, 0 };
    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    status = WinVerifyTrust(nullptr, &policyGUID, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGUID, &trustData);
    return status == ERROR_SUCCESS;
}

vector<DWORD> getProcessListToolhelp() {
    vector<DWORD> pids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snapshot, &pe)) {
        do {
            pids.push_back(pe.th32ProcessID);
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return pids;
}

vector<DWORD> getProcessListNative() {
    vector<DWORD> pids;
    ULONG size = 0x10000;
    PBYTE buffer = new BYTE[size];
    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        delete[] buffer;
        return pids;
    }
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        delete[] buffer;
        size *= 2;
        buffer = new BYTE[size];
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
    }
    if (!NT_SUCCESS(status)) {
        delete[] buffer;
        return pids;
    }
    BYTE* ptr = buffer;
    while (true) {
        SYSTEM_PROCESS_INFORMATION* spi = (SYSTEM_PROCESS_INFORMATION*)ptr;
        if (spi->UniqueProcessId != NULL) {
            pids.push_back((DWORD)(uintptr_t)spi->UniqueProcessId);
        }
        if (spi->NextEntryOffset == 0) break;
        ptr += spi->NextEntryOffset;
    }
    delete[] buffer;
    return pids;
}

void detectHiddenProcesses() {
    cout << "[*] Checking hidden/unlinked processes...\n";
    vector<DWORD> tlList = getProcessListToolhelp();
    vector<DWORD> nativeList = getProcessListNative();
    map<DWORD, bool> tlMap, nativeMap;
    for (auto pid : tlList) tlMap[pid] = true;
    for (auto pid : nativeList) nativeMap[pid] = true;
    bool found = false;
    for (auto pid : nativeList) {
        if (tlMap.find(pid) == tlMap.end()) {
            cout << "[!!] Process " << pid << " in native list but missing in Toolhelp32 - possible hidden/rootkit\n";
            found = true;
        }
    }
    if (!found) cout << "[+] No hidden processes detected.\n";
}

bool readFileToBuffer(const wstring& path, vector<BYTE>& buffer) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file) return false;
    streamsize size = file.tellg();
    if (size <= 0) return false;
    file.seekg(0, ios::beg);
    buffer.resize(static_cast<size_t>(size));
    return file.read(reinterpret_cast<char*>(buffer.data()), size).good();
}

bool bufferDiffers(const BYTE* a, const BYTE* b, size_t size) {
    for (size_t i = 0; i < size; i++) if (a[i] != b[i]) return true;
    return false;
}

wstring toLowerW(const wstring& str) {
    wstring res = str;
    transform(res.begin(), res.end(), res.begin(), ::towlower);
    return res;
}

void detectInlineHooks() {
    cout << "[*] Scanning system DLLs for inline hooks...\n";
    const wchar_t* dlls[] = { L"ntdll.dll", L"kernel32.dll" };
    WCHAR sysPath[MAX_PATH];
    GetSystemDirectory(sysPath, MAX_PATH);
    for (auto dll : dlls) {
        wstring diskPath = wstring(sysPath) + L"\\" + dll;
        vector<BYTE> diskData;
        if (!readFileToBuffer(diskPath, diskData)) continue;
        HMODULE mod = GetModuleHandle(dll);
        if (!mod) continue;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
        size_t textSize = 0;
        BYTE* inMemCode = nullptr;
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
            if (memcmp(section->Name, ".text", 5) == 0) {
                textSize = section->SizeOfRawData;
                inMemCode = (BYTE*)mod + section->VirtualAddress;
                break;
            }
        }
        if (!inMemCode || textSize == 0) continue;
        if (diskData.size() < textSize) continue;
        if (bufferDiffers(inMemCode, diskData.data() + (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)), textSize)) {
            wcout << L"[!!] Inline hook detected in " << dll << L"\n";
        }
        else {
            wcout << L"[+] No inline hook in " << dll << L"\n";
        }
    }
}

void checkSyscallStub(const char* funcName) {
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return;
    void* addr = (void*)GetProcAddress(ntdll, funcName);
    if (!addr) return;
    BYTE* code = (BYTE*)addr;
    if (code[0] != 0x4c || code[1] != 0x8b || code[2] != 0xd1) {
        cout << "[!!] Possible user-mode hook detected on " << funcName << "\n";
    }
    else {
        cout << "[+] " << funcName << " syscall stub clean\n";
    }
}

void detectSyscallHooks() {
    cout << "[*] Checking syscall stubs...\n";
    const char* syscalls[] = { "NtCreateFile", "NtOpenProcess", "NtWriteVirtualMemory", "NtReadVirtualMemory" };
    for (auto func : syscalls) checkSyscallStub(func);
}

void detectIATHooksCurrent() {
    cout << "[*] Checking IAT hooks in current process...\n";
    HMODULE mod = GetModuleHandle(NULL);
    if (!mod) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    DWORD importDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirRVA == 0) return;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)mod + importDirRVA);
    for (; importDesc->Name; importDesc++) {
        char* modName = (char*)((BYTE*)mod + importDesc->Name);
        PIMAGE_THUNK_DATA thunkOrig = (PIMAGE_THUNK_DATA)((BYTE*)mod + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkFirst = (PIMAGE_THUNK_DATA)((BYTE*)mod + importDesc->FirstThunk);
        for (; thunkOrig->u1.AddressOfData; thunkOrig++, thunkFirst++) {
            if (!(thunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)mod + thunkOrig->u1.AddressOfData);
                FARPROC funcAddr = (FARPROC)thunkFirst->u1.Function;
                HMODULE importedMod = GetModuleHandleA(modName);
                FARPROC realAddr = GetProcAddress(importedMod, (LPCSTR)importByName->Name);
                if (funcAddr != realAddr) {
                    cout << "[!!] IAT Hook detected: " << modName << "!" << importByName->Name << "\n";
                }
            }
        }
    }
}

bool isDriverUnsigned(const wstring& path) {
    return !verifyFileSignature(path);
}

void detectUnsignedDrivers() {
    cout << "[*] Scanning loaded drivers for unsigned...\n";
    const int maxDrivers = 2048;
    LPVOID drivers[maxDrivers];
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        cout << "[!] Failed to enumerate device drivers.\n";
        return;
    }
    int count = cbNeeded / sizeof(LPVOID);
    for (int i = 0; i < count; ++i) {
        TCHAR driverPath[MAX_PATH] = { 0 };
        if (GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH) == 0) continue;
        wstring driverWPath(driverPath);
        wstring lowerPath = toLowerW(driverWPath);
        if (lowerPath.find(L"temp") != wstring::npos || lowerPath.find(L"\\drivers\\") == wstring::npos) continue;
        if (isDriverUnsigned(driverWPath)) {
            wcout << L"[!!] Unsigned driver detected: " << driverWPath << L"\n";
        }
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    cout << "CAT User-Mode Rootkit Detector\n\n";
    detectHiddenProcesses();
    cout << "\n";
    detectInlineHooks();
    cout << "\n";
    detectSyscallHooks();
    cout << "\n";
    detectIATHooksCurrent();
    cout << "\n";
    detectUnsignedDrivers();
    cout << "\nScan Complete\n";
    return 0;
}
