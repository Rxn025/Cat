// udc.exe
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

using namespace std;

static bool verifyEmbeddedSignature(const wstring& file) {
    LONG status;
    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO), nullptr, file.c_str(), nullptr, 0 };
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

static string fileToHex(const vector<BYTE>& data) {
    stringstream ss;
    ss << hex << setfill('0');
    for (BYTE b : data) ss << setw(2) << (int)b;
    return ss.str();
}

static bool readFileToBuffer(const wstring& path, vector<BYTE>& buffer) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file) return false;
    streamsize size = file.tellg();
    if (size <= 0) return false;
    file.seekg(0, ios::beg);
    buffer.resize(static_cast<size_t>(size));
    return file.read(reinterpret_cast<char*>(buffer.data()), size).good();
}

static string sha256HashFile(const wstring& path) {
    vector<BYTE> data;
    if (!readFileToBuffer(path, data)) return "";
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContext(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        return "";
    }
    if (!CryptHashData(hash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);
        return "";
    }
    BYTE hashBytes[32];
    DWORD hashSize = 32;
    if (!CryptGetHashParam(hash, HP_HASHVAL, hashBytes, &hashSize, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);
        return "";
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return fileToHex(vector<BYTE>(hashBytes, hashBytes + hashSize));
}

static wstring toLowerW(const wstring& str) {
    wstring res = str;
    transform(res.begin(), res.end(), res.begin(), ::towlower);
    return res;
}

static bool isMicrosoftSigned(const wstring& path) {
    if (!verifyEmbeddedSignature(path)) return false;
    wstring lpFileName = path;
    if (lpFileName.find(L"System32") == wstring::npos && lpFileName.find(L"Windows") == wstring::npos) return false;
    return true;
}

static void scanUnsignedKernelDrivers() {
    const int maxDrivers = 2048;
    LPVOID drivers[maxDrivers];
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        cout << "[!] EnumDeviceDrivers failed\n";
        return;
    }
    int count = cbNeeded / sizeof(LPVOID);
    cout << "[*] Scanning " << count << " loaded kernel drivers...\n";
    for (int i = 0; i < count; ++i) {
        TCHAR driverPath[MAX_PATH] = { 0 };
        if (GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH) == 0) continue;
        wstring driverWPath(driverPath);
        wstring lowerPath = toLowerW(driverWPath);
        if (lowerPath.find(L"temp") != wstring::npos || lowerPath.find(L"\\drivers\\") == wstring::npos) continue;
        bool signedStatus = verifyEmbeddedSignature(driverWPath);
        if (!signedStatus) {
            string hash = sha256HashFile(driverWPath);
            wcout << L"[!!] Unsigned kernel driver: " << driverWPath << L"\n";
            cout << "    SHA256: " << (hash.empty() ? "N/A" : hash.substr(0, 64)) << "\n";
        }
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    cout << "UDC, Unsigned Driver Check\n";
    scanUnsignedKernelDrivers();
    cout << "Scan Complete!\n";
    return 0;
}
