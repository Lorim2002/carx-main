// github.com/majorkadev

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <ctime>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <algorithm>

// Windows API definitions
#define ProcessDebugPort 7
#define ProcessDebugObjectHandle 30
#define ProcessDebugFlags 31

// Native API structures
typedef enum _DEBUG_PROCESS_INFO_CLASS {
    DebugPort = ProcessDebugPort,
    DebugObjectHandle = ProcessDebugObjectHandle,
    DebugFlags = ProcessDebugFlags
} DEBUG_PROCESS_INFO_CLASS;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN DEBUG_PROCESS_INFO_CLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

// Basic anti-debugging functions
bool IsDebuggerPresentCheck() {
    return IsDebuggerPresent();
}

bool CheckRemoteDebugger() {
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    return isDebuggerPresent;
}

bool DetectDebugger() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
    }
    return false;
}

// Anti-debugging and anti-RE functions
bool CheckDebuggerProcesses() {
    const char* debuggers[] = {
        "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "ollydbg.exe", "ghidra.exe", "dnspy.exe", "cheatengine-x86_64.exe",
        "hxd.exe", "windbg.exe", "radare2.exe", "pestudio.exe",
        "processhacker.exe", "scylla.exe", "protection_id.exe", "charles.exe",
        "wireshark.exe", "fiddler.exe"
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            char processName[MAX_PATH];
            size_t converted;
            wcstombs_s(&converted, processName, sizeof(processName), pe32.szExeFile, _TRUNCATE);
            for (const char* debugger : debuggers) {
                if (_stricmp(processName, debugger) == 0) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

bool CheckDebuggerWindows() {
    const char* windowNames[] = {
        "x64dbg", "IDA", "Ollydbg", "Ghidra", 
        "dnSpy", "Cheat Engine", "WinDbg", 
        "Process Hacker", "Scylla", "Protection ID"
    };

    for (const char* name : windowNames) {
        if (FindWindowA(NULL, name) != NULL) {
            return true;
        }
    }
    return false;
}

bool CheckDebuggerWithNtQuery() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return false;

    // Debug port check
    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        DebugPort,
        &debugPort,
        sizeof(debugPort),
        nullptr
    );

    if (NT_SUCCESS(status) && debugPort != 0) {
        return true;
    }

    // Debug flags check
    DWORD_PTR debugFlags = 0;
    status = NtQueryInformationProcess(
        GetCurrentProcess(),
        DebugFlags,
        &debugFlags,
        sizeof(debugFlags),
        nullptr
    );

    return (NT_SUCCESS(status) && debugFlags == 0);
}

bool AdvancedAntiDebug() {
    BOOL isDebuggerPresent = FALSE;
    
    // Timing check
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    OutputDebugStringA("Anti-Debug Check");
    QueryPerformanceCounter(&end);
    
    // If debugger is present, OutputDebugString will take longer
    if ((end.QuadPart - start.QuadPart) > (freq.QuadPart / 100)) {
        return true;
    }
    
    // Hardware breakpoint check
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
    }

    // Native API debug checks
    if (CheckDebuggerWithNtQuery()) {
        return true;
    }

    // Parent process check
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32FirstW(snapshot, &pe32)) {
            DWORD currentPid = GetCurrentProcessId();
            DWORD parentPid = 0;
            
            do {
                if (pe32.th32ProcessID == currentPid) {
                    parentPid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));

            if (parentPid != 0) {
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPid);
                if (hParent != NULL) {
                    char parentPath[MAX_PATH];
                    if (GetModuleFileNameExA(hParent, NULL, parentPath, MAX_PATH)) {
                        std::string parentName = parentPath;
                        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);
                        
                        const char* suspiciousParents[] = {
                            "x64dbg", "ida", "ollydbg", "windbg", "devenv.exe"
                        };

                        for (const char* suspicious : suspiciousParents) {
                            if (parentName.find(suspicious) != std::string::npos) {
                                CloseHandle(hParent);
                                CloseHandle(snapshot);
                                return true;
                            }
                        }
                    }
                    CloseHandle(hParent);
                }
            }
        }
        CloseHandle(snapshot);
    }

    return false;
}

void setConsoleUTF8() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // Enable virtual terminal processing for modern console features
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

// ANSI Color Codes
const char* GREEN = "\033[32m";
const char* YELLOW = "\033[33m";
const char* RESET = "\033[0m";
const char* RED = "\033[31m";

bool isCarXWindowActive() {
    HWND activeWindow = GetForegroundWindow();
    if (activeWindow == NULL) return false;

    char windowTitle[256];
    GetWindowTextA(activeWindow, windowTitle, sizeof(windowTitle));
    return (std::string(windowTitle).find("Drift Racing Online") != std::string::npos);
}

bool isCarXRunning() {
    HWND window = FindWindowA(NULL, "Drift Racing Online");
    return (window != NULL);
}

void pressH(int holdTime, int releaseTime) {
    keybd_event('H', 0, 0, 0);
    Sleep(holdTime);
    keybd_event('H', 0, KEYEVENTF_KEYUP, 0);
    Sleep(releaseTime);
}

enum PoliceMode {
    NORMAL,
    FAST,
    ULTRA,
    STROBO      // New advanced strobo mode
};

// Strobo pattern sequence structure
struct StroboSequence {
    int holdTime;
    int releaseTime;
    int repeatCount;
};

void executeStroboPattern(const std::vector<StroboSequence>& pattern) {
    for (const auto& seq : pattern) {
        for (int i = 0; i < seq.repeatCount; i++) {
            pressH(seq.holdTime, seq.releaseTime);
        }
    }
}

void policeFlasher(PoliceMode mode) {
    switch (mode) {
        case NORMAL:
            pressH(30, 30);
            pressH(30, 30);
            Sleep(100);
            pressH(30, 30);
            pressH(30, 30);
            Sleep(200);
            break;
            
        case FAST:
            pressH(20, 20);
            Sleep(50);
            pressH(20, 20);
            Sleep(50);
            pressH(20, 20);
            Sleep(50);
            pressH(20, 20);
            Sleep(100);
            break;
            
        case ULTRA:
            for (int i = 0; i < 3; i++) {
                pressH(15, 15);
                pressH(15, 15);
            }
            Sleep(150);
            break;
            
        case STROBO: {
            // Complex strobo pattern sequences
            std::vector<std::vector<StroboSequence>> patterns = {
                // Pattern 1: Quick triple flash
                {
                    {10, 10, 3},    // Quick triple burst
                    {0, 100, 1},    // Short pause
                    {15, 15, 2},    // Double flash
                    {0, 150, 1}     // Medium pause
                },
                // Pattern 2: Alternating speed
                {
                    {20, 20, 2},    // Normal double
                    {10, 10, 4},    // Quick quad
                    {0, 100, 1},    // Pause
                    {15, 15, 2},    // Final double
                    {0, 150, 1}     // End pause
                },
                // Pattern 3: Burst mode
                {
                    {8, 8, 6},      // Ultra fast burst
                    {0, 120, 1},    // Pause
                    {25, 25, 2},    // Slow double
                    {0, 150, 1}     // End pause
                }
            };
            
            // Execute a random pattern
            static int currentPattern = 0;
            executeStroboPattern(patterns[currentPattern]);
            currentPattern = (currentPattern + 1) % patterns.size();
            break;
        }
    }
}

void clearScreen() {
    system("cls");
}

void showMenu(bool isSpamming, bool isPoliceMode, PoliceMode currentMode, int delayTime) {
    clearScreen();
    bool carxRunning = isCarXRunning();
    
    std::cout << YELLOW;
    std::cout << "\n╔════════════════════════════════════════════════╗\n";
    std::cout << "║            CarX Selector Spammer               ║\n";
    std::cout << "║                  @majorkadev                   ║\n";
    std::cout << "╚════════════════════════════════════════════════╝\n" << RESET;
    std::cout << RED << "WARNING: Use this tool for legitimate purposes only. Unauthorized use is prohibited.\n\n" << RESET;

    // CarX Status
    std::cout << "CarX Status: ";
    if (carxRunning) {
        std::cout << GREEN << "Running" << RESET << "\n";
    } else {
        std::cout << YELLOW << "Waiting for CarX..." << RESET << "\n";
    }
    
    // Mode Status
    std::cout << "Mode: ";
    if (isSpamming) std::cout << "Normal Spam Active (" << delayTime << "ms)\n";
    else if (isPoliceMode) {
        std::cout << "Police Mode - ";
        switch (currentMode) {
            case NORMAL: std::cout << "Normal Pattern\n"; break;
            case FAST: std::cout << "Fast Pattern\n"; break;
            case ULTRA: std::cout << "Ultra Pattern\n"; break;
            case STROBO: std::cout << "Strobo Pattern\n"; break;
        }
    }
    else std::cout << "Waiting...\n";
    
    std::cout << "\nControls:\n";
    std::cout << "[F6] Toggle Normal Spam Mode\n";
    std::cout << "[F5] Toggle Police Flasher Mode\n";
    
    if (isPoliceMode) {
        std::cout << "\nPolice Mode Patterns:\n";
        std::cout << "[1] Normal Flasher Pattern\n";
        std::cout << "[2] Fast Flasher Pattern\n";
        std::cout << "[3] Ultra Flasher Pattern\n";
        std::cout << "[4] Advanced Strobo Pattern\n";
    }
    
    if (isSpamming) {
        std::cout << "\nSpeed Control:\n";
        std::cout << "[F7] Decrease Speed\n";
        std::cout << "[F8] Increase Speed\n";
    }
    
    std::cout << "\n[ESC] Exit Program\n";
}

void showWelcomeScreen() {
    // Clear screen
    system("cls");
    
    // ANSI Escape codes for colors
    const char* CYAN = "\033[36m";
    const char* MAGENTA = "\033[35m";
    const char* BRIGHT_BLUE = "\033[94m";
    const char* BRIGHT_GREEN = "\033[92m";
    const char* BRIGHT_YELLOW = "\033[93m";
    
    // Animation frames for loading
    const char* frames[] = {"|", "/", "-", "\\"};
    
    // Show logo with typing effect
    std::cout << BRIGHT_BLUE;
    const char* logo[] = {

        " A lightweight headlight control automation tool for CarX Drift Racing Online.",
        " This tool is for educational purposes only. Use at your own risk.                                     "
    };
    
    for(const char* line : logo) {
        std::cout << line << "\n";
        Sleep(100);
    }
    
    
    // Developer-style loading logs
    std::cout << "\n\n" << BRIGHT_GREEN;
    
    std::cout << "[+] Initializing loader..." << std::endl;
    Sleep(400);
    
    std::cout << "[+] Loading security modules..." << std::endl;
    Sleep(650);
    std::cout << "[+] Security modules loaded successfully" << std::endl;
    Sleep(300);

    std::cout << "[+] Checking system compatibility..." << std::endl;
    Sleep(550);
    std::cout << "[+] System check passed" << std::endl;
    Sleep(300);

    std::cout << "[+] Setting up environment..." << std::endl;
    Sleep(450);
    std::cout << "[+] Environment configured" << std::endl;
    Sleep(300);

    std::cout << BRIGHT_BLUE << "\n[INFO] All systems operational. Starting main application..." << std::endl;
    Sleep(1000);

    std::cout << BRIGHT_BLUE << "\n[GITHUB] @majorkadev" << std::endl;
    Sleep(2000);
    
    // Clear screen after animation
    Sleep(500);
    system("cls");
}

int main() {
    // Set UTF-8 and enable ANSI escape sequences
    setConsoleUTF8();
    
    // Show welcome screen
    showWelcomeScreen();
    
    // Initial anti-debug check
    if (IsDebuggerPresentCheck() || 
        CheckRemoteDebugger() || 
        DetectDebugger() || 
        CheckDebuggerProcesses() || 
        CheckDebuggerWindows() || 
        AdvancedAntiDebug()) {
        MessageBoxA(NULL, "This program cannot run under a debugger.", "Error", MB_ICONERROR);
        exit(1);
    }
    
    setConsoleUTF8();  // Set UTF-8 encoding
    SetConsoleTitleA("CarX Selector Spammer");
    
    bool isSpamming = false;
    bool isPoliceMode = false;
    int delayTime = 20;
    PoliceMode currentPoliceMode = NORMAL;
    
    showMenu(isSpamming, isPoliceMode, currentPoliceMode, delayTime);
    
    DWORD lastCheckTime = GetTickCount();
    const DWORD CHECK_INTERVAL = 1000; 
    
    while (true) {
        
        DWORD currentTime = GetTickCount();
        if (currentTime - lastCheckTime >= CHECK_INTERVAL) {
            if (IsDebuggerPresentCheck() || 
                CheckRemoteDebugger() || 
                DetectDebugger() || 
                CheckDebuggerProcesses() || 
                CheckDebuggerWindows() || 
                AdvancedAntiDebug()) {
                MessageBoxA(NULL, "Debugger detected! Program will exit.", "Security Alert", MB_ICONERROR);
                exit(1);
            }
            lastCheckTime = currentTime;
        }

        bool shouldUpdateMenu = false;
        static bool lastCarXState = false;
        bool currentCarXState = isCarXRunning();
        
        // Update menu if CarX state changes
        if (lastCarXState != currentCarXState) {
            shouldUpdateMenu = true;
            lastCarXState = currentCarXState;
        }
        
        if (GetAsyncKeyState(VK_F6) & 1) {
            isSpamming = !isSpamming;
            isPoliceMode = false;
            shouldUpdateMenu = true;
        }

        if (GetAsyncKeyState(VK_F5) & 1) {
            isPoliceMode = !isPoliceMode;
            isSpamming = false;
            shouldUpdateMenu = true;
        }

        if (isPoliceMode) {
            if (GetAsyncKeyState('1') & 1) {
                currentPoliceMode = NORMAL;
                shouldUpdateMenu = true;
            }
            else if (GetAsyncKeyState('2') & 1) {
                currentPoliceMode = FAST;
                shouldUpdateMenu = true;
            }
            else if (GetAsyncKeyState('3') & 1) {
                currentPoliceMode = ULTRA;
                shouldUpdateMenu = true;
            }
            else if (GetAsyncKeyState('4') & 1) {
                currentPoliceMode = STROBO;
                shouldUpdateMenu = true;
            }
        }
        
        if (GetAsyncKeyState(VK_F7) & 1) {
            delayTime = min(100, delayTime + 5);
            shouldUpdateMenu = true;
        }
        if (GetAsyncKeyState(VK_F8) & 1) {
            delayTime = max(5, delayTime - 5);
            shouldUpdateMenu = true;
        }
        
        if (GetAsyncKeyState(VK_ESCAPE)) {
            break;
        }
        
        if (shouldUpdateMenu) {
            showMenu(isSpamming, isPoliceMode, currentPoliceMode, delayTime);
        }
        
        if (isCarXWindowActive()) {
            if (isSpamming) {
                pressH(delayTime, delayTime);
            }
            else if (isPoliceMode) {
                policeFlasher(currentPoliceMode);
            }
        }
        
        Sleep(1);
    }
    
    clearScreen();
    std::cout << "\n Program closed. See you next time!\n\n";
    Sleep(1500);
    return 0;

    // github.com/majorkadev
} 