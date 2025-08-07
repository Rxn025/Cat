#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <Softpub.h>
#include <shlwapi.h>
#include <tchar.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <filesystem>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")

using namespace std;

// ----------- Utility: SHA256 Hashing -----------
string sha256(const string& file) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE buffer[8192];
    DWORD bytesRead;
    HANDLE hFile = CreateFile(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "error";

    CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash);
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead) {
        CryptHashData(hash, buffer, bytesRead, 0);
    }
    BYTE hashVal[32];
    DWORD hashLen = 32;
    CryptGetHashParam(hash, HP_HASHVAL, hashVal, &hashLen, 0);
    CloseHandle(hFile);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);

    stringstream ss;
    for (DWORD i = 0; i < hashLen; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hashVal[i];
    return ss.str();
}

// ----------- Check if the file is signed -----------
bool isSigned(const string& path) {
    LONG status;
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wstring(path.begin(), path.end()).c_str();

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    status = WinVerifyTrust(NULL, &policyGUID, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);
    return status == ERROR_SUCCESS;
}

// ----------- Kill Process by PID -----------
void killProcess(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        TerminateProcess(hProc, 0);
        CloseHandle(hProc);
    }
}

// ----------- Self-delete on threat -----------
void selfDelete() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    string command = "cmd /c timeout /t 1 & del \"" + string(path) + "\"";
    system(command.c_str());
    exit(0);
}

// ----------- Get Process Path by PID -----------
string getProcPath(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return "unknown";
    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProc, 0, path, &size))
        return path;
    CloseHandle(hProc);
    return "unknown";
}

// ----------- Main Port Scanner and Verifier -----------
void scanAndEliminate() {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    cout << "[+] Scanning open TCP ports...\n\n";
    for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
        MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
        DWORD localPort = ntohs((u_short)row.dwLocalPort);
        DWORD remotePort = ntohs((u_short)row.dwRemotePort);
        string state = (row.dwState == MIB_TCP_STATE_LISTEN) ? "LISTENING" : (row.dwState == MIB_TCP_STATE_ESTAB ? "ESTABLISHED" : "OTHER");

        if (state == "LISTENING" || state == "ESTABLISHED") {
            string procPath = getProcPath(row.dwOwningPid);
            bool signedApp = isSigned(procPath);
            string fileHash = sha256(procPath);

            cout << "PID: " << row.dwOwningPid << " | Port: " << localPort
                 << " | State: " << state
                 << "\nPath: " << procPath
                 << "\nSigned: " << (signedApp ? "Yes" : "No")
                 << "\nSHA256: " << fileHash.substr(0, 16) << "...\n";

            // Fake secure connection detection (simulate)
            bool secure = fileHash.substr(0, 2) == "e3"; // Random test rule

            if (!secure) {
                cout << "[!] Insecure sender detected. Sending kill and wiping trace...\n";
                // Simulate sending close command to attacker (optional)
                selfDelete(); // Kill self to avoid trace
            }

            if (!signedApp) {
                cout << "[?] Do you want to eliminate this process? (y/n): ";
                char input;
                cin >> input;
                if (input == 'y' || input == 'Y') {
                    killProcess(row.dwOwningPid);
                    cout << "[+] Process terminated.\n\n";
                }
            }
        }
    }
    free(tcpTable);
}

// ----------- MAIN -----------
int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    scanAndEliminate();
    WSACleanup();
    return 0;
}
