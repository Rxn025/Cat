// cat cli
#include <iostream>
#include <string>
#include <cstdlib> 

using namespace std;

void printMenu() {
    cout << "CAT\n";
    cout << "Select a module to run:\n";
    cout << "1. Unsigned Driver Check (udc.exe)\n";
    cout << "2. Rootkit Detector (rd.exe)\n";
    cout << "3. Bootkit Detector (bk.exe)\n";
    cout << "4. Hidden Process Detector (hpd.exe)\n";
    cout << "5. Driver Signature Enforcement (dse.exe)\n";
    cout << "6. Hook & Injection Scanner (his.exe)\n";
    cout << "7. Unlinked DLL Detector (udd.exe)\n";
    cout << "8. DNS Hijack Detector (dhd.exe)\n";
    cout << "9. Firewall Tamper Detector (ftd.exe)\n";
    cout << "10. Persistence Scanner (ps.exe)\n";
    cout << "0. Exit\n";
    cout << "Enter choice: ";
}

int main() {
    while (true) {
        printMenu();
        int choice;
        cin >> choice;

        if (choice == 0) {
            cout << "Exiting CAT...\n";
            break;
        }

        string cmd;

        switch (choice) {
            case 1: cmd = "udc.exe"; break;
            case 2: cmd = "rd.exe"; break;
            case 3: cmd = "bk.exe"; break;
            case 4: cmd = "hpd.exe"; break;
            case 5: cmd = "dse.exe"; break;
            case 6: cmd = "his.exe"; break;
            case 7: cmd = "udd.exe"; break;
            case 8: cmd = "dhd.exe"; break;
            case 9: cmd = "ftd.exe"; break;
            case 10: cmd = "ps.exe"; break;
            default:
                cout << "Invalid choice, try again.\n";
                continue;
        }

        cout << "Running " << cmd << "...\n";
        int ret = system(cmd.c_str());
        if (ret != 0) {
            cout << "Failed to run " << cmd << ". Make sure the executable is in the same folder.\n";
        }
        cout << "Press Enter to continue...";
        cin.ignore();
        cin.get();
    }
    return 0;
}
