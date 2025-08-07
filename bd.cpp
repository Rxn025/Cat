// bd.cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <winioctl.h>
#include <cfgmgr32.h>

using namespace std;

#pragma comment(lib, "cfgmgr32.lib")

bool readRawDiskSector(const wchar_t* devicePath, DWORD sector, BYTE* buffer, DWORD size) {
    HANDLE hDisk = CreateFileW(devicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDisk == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li;
    li.QuadPart = sector * 512ULL;
    if (!SetFilePointerEx(hDisk, li, nullptr, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return false;
    }

    DWORD bytesRead = 0;
    bool success = ReadFile(hDisk, buffer, size, &bytesRead, nullptr) && (bytesRead == size);
    CloseHandle(hDisk);
    return success;
}

void printHex(const BYTE* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

bool checkMBRSignature(const BYTE* sector) {
    return sector[510] == 0x55 && sector[511] == 0xAA;
}

bool detectSuspiciousMBR(const BYTE* sector) {
    // Simple heuristic: suspicious if large part of MBR code contains zeros or uncommon values
    int zeroCount = 0;
    for (int i = 0; i < 446; i++) {
        if (sector[i] == 0x00) zeroCount++;
    }
    if (zeroCount > 100) return true; // unusually many zeros in code area
    // More heuristics can be added here
    return false;
}

void scanMBR() {
    BYTE sector[512] = { 0 };
    if (!readRawDiskSector(L"\\\\.\\PhysicalDrive0", 0, sector, 512)) {
        cout << "[!] Failed to read MBR. Run as admin and on physical drive 0.\n";
        return;
    }
    cout << "[*] Scanning MBR signature...\n";
    if (!checkMBRSignature(sector)) {
        cout << "[!!] Invalid MBR signature detected!\n";
    }
    else {
        cout << "[+] Valid MBR signature found.\n";
    }
    if (detectSuspiciousMBR(sector)) {
        cout << "[!!] Suspicious MBR code pattern detected.\n";
    }
    else {
        cout << "[+] MBR code looks normal.\n";
    }
    // Optionally print MBR bytes (commented)
    // printHex(sector, 512);
}

bool readEFIStartupEntries() {
    DWORD size = 0;
    UINT32 ret = GetFirmwareEnvironmentVariableW(L"BootOrder", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", nullptr, 0);
    if (ret == 0) {
        if (GetLastError() == ERROR_NOACCESS) {
            cout << "[!] Access denied reading EFI variables. Run as admin.\n";
        }
        else {
            cout << "[*] No EFI BootOrder variable found. Possibly BIOS boot mode.\n";
        }
        return false;
    }
    cout << "[*] EFI BootOrder variable detected.\n";

    // Reading BootOrder
    size = 512;
    vector<BYTE> buffer(size);
    ret = GetFirmwareEnvironmentVariableW(L"BootOrder", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", buffer.data(), size);
    if (ret == 0) {
        cout << "[!] Failed to read EFI BootOrder variable content.\n";
        return false;
    }
    int entryCount = ret / 2;
    cout << "[*] EFI BootOrder entries count: " << entryCount << "\n";

    for (int i = 0; i < entryCount; i++) {
        wchar_t entryName[20];
        swprintf(entryName, 20, L"Boot%04X", buffer[i * 2] | (buffer[i * 2 + 1] << 8));
        BYTE entryData[1024] = { 0 };
        ret = GetFirmwareEnvironmentVariableW(entryName, L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", entryData, sizeof(entryData));
        if (ret == 0) {
            cout << "[!] Failed to read EFI entry " << ws2s(entryName) << "\n";
            continue;
        }
        wcout << L"[+] EFI Boot entry found: " << entryName << L"\n";
        // Parsing EFI boot entries is complex, here just raw size and partial data
    }
    return true;
}

string ws2s(const wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    cout << "CAT Bootkit Detector\n\n";

    scanMBR();
    cout << "\n";

    cout << "[*] Checking EFI boot entries...\n";
    if (!readEFIStartupEntries()) {
        cout << "[*] EFI boot entries scan skipped or unavailable.\n";
    }

    cout << "\n Scan Complete\n";
    return 0;
}
