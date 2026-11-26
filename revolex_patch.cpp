#include "revolex_offsets.hpp"

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

using Address = std::uintptr_t;
using Clock = std::chrono::steady_clock;

std::string ErrorMessage(DWORD error = GetLastError()) {
    return std::error_code(static_cast<int>(error), std::system_category()).message();
}

std::string Hex(Address value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return stream.str();
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const bool result = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE;
    CloseHandle(token);
    return result && elevation.TokenIsElevated != 0;
}

std::filesystem::path ExecutablePath() {
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    return std::filesystem::path(std::wstring(buffer.data(), length));
}

std::wstring Quote(const std::wstring& value) {
    std::wstring result = L"\"";
    for (const wchar_t character : value) {
        if (character == L'\"') {
            result += L"\\\"";
        } else {
            result += character;
        }
    }
    result += L"\"";
    return result;
}

bool Elevate(int argc, wchar_t** argv) {
    std::wstring parameters;
    for (int index = 1; index < argc; ++index) {
        if (index > 1) {
            parameters += L' ';
        }
        parameters += Quote(argv[index]);
    }
    const auto executable = ExecutablePath();
    const auto result = ShellExecuteW(nullptr, L"runas", executable.c_str(), parameters.c_str(), executable.parent_path().c_str(), SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        std::cerr << "[!] Elevation failed: " << ErrorMessage(static_cast<DWORD>(reinterpret_cast<INT_PTR>(result))) << '\n';
        return false;
    }
    return true;
}

bool ReadMemory(HANDLE process, Address address, void* output, SIZE_T size) {
    SIZE_T completed = 0;
    return ReadProcessMemory(process, reinterpret_cast<const void*>(address), output, size, &completed) && completed == size;
}

template <std::size_t N>
bool ReadMemory(HANDLE process, Address address, std::array<std::uint8_t, N>& output) {
    return ReadMemory(process, address, output.data(), output.size());
}

bool WriteMemory(HANDLE process, Address address, const void* data, SIZE_T size) {
    DWORD oldProtection = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        return false;
    }
    SIZE_T completed = 0;
    const bool written = WriteProcessMemory(process, reinterpret_cast<void*>(address), data, size, &completed) && completed == size;
    DWORD ignored = 0;
    VirtualProtectEx(process, reinterpret_cast<void*>(address), size, oldProtection, &ignored);
    if (!written) {
        return false;
    }
    std::vector<std::uint8_t> verification(size);
    return ReadMemory(process, address, verification.data(), size) && std::memcmp(verification.data(), data, size) == 0;
}

template <std::size_t N>
bool WriteMemory(HANDLE process, Address address, const std::array<std::uint8_t, N>& data) {
    return WriteMemory(process, address, data.data(), data.size());
}

bool ProcessRunning(HANDLE process) {
    return WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
}

bool DriverRunning() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
        return false;
    }
    SC_HANDLE service = OpenServiceW(manager, L"ROGMS", SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return false;
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD required = 0;
    const bool queried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &required) != FALSE;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return queried && status.dwCurrentState == SERVICE_RUNNING;
}

Address ImageBase(HANDLE process) {
    HMODULE module = nullptr;
    DWORD required = 0;
    if (EnumProcessModulesEx(process, &module, sizeof(module), &required, LIST_MODULES_64BIT) && required >= sizeof(module)) {
        return reinterpret_cast<Address>(module);
    }
    using NtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (query == nullptr) {
        return 0;
    }
    PROCESS_BASIC_INFORMATION information{};
    if (query(process, ProcessBasicInformation, &information, sizeof(information), nullptr) < 0 || information.PebBaseAddress == nullptr) {
        return 0;
    }
    Address base = 0;
    const auto imageBaseAddress = reinterpret_cast<Address>(information.PebBaseAddress) + 0x10;
    return ReadMemory(process, imageBaseAddress, &base, sizeof(base)) ? base : 0;
}

bool ImageReady(HANDLE process, Address base) {
    for (const auto& patch : revolex::kBranchPatches) {
        std::array<std::uint8_t, 6> current{};
        if (ReadMemory(process, base + patch.rva, current) && (current == patch.expected || current == patch.replacement)) {
            return true;
        }
    }
    return false;
}

bool RunProgramDetected(HANDLE process, Address base) {
    std::array<std::uint8_t, 3> current{};
    return ReadMemory(process, base + revolex::kRunProgramStateRva, current) && current == revolex::kRunProgramState;
}

struct RemoteString {
    std::string text;
    std::uint64_t length = 0;
    std::uint64_t capacity = 0;
    Address pointer = 0;
};

bool ReadRemoteString(HANDLE process, Address address, RemoteString& result) {
    std::array<std::uint8_t, 32> object{};
    if (!ReadMemory(process, address, object)) {
        return false;
    }
    Address pointer = 0;
    std::memcpy(&pointer, object.data(), sizeof(pointer));
    std::memcpy(&result.length, object.data() + 16, sizeof(result.length));
    std::memcpy(&result.capacity, object.data() + 24, sizeof(result.capacity));
    result.pointer = pointer;
    if (result.length > 4096 || result.capacity > 4096 || result.length > result.capacity) {
        return false;
    }
    std::array<char, 4097> buffer{};
    if (result.capacity > 15) {
        if (pointer == 0 || !ReadMemory(process, pointer, buffer.data(), static_cast<SIZE_T>(result.length + 1))) {
            return false;
        }
    } else {
        std::memcpy(buffer.data(), object.data(), 16);
    }
    result.text.assign(buffer.data(), static_cast<std::size_t>(result.length));
    return true;
}

template <typename T>
void Append(std::vector<std::uint8_t>& output, const T& value) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
    output.insert(output.end(), bytes, bytes + sizeof(value));
}

Address AllocateTargetHeap(HANDLE process, std::uint32_t size) {
    const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (kernel == nullptr) {
        return 0;
    }
    const auto getProcessHeap = reinterpret_cast<Address>(GetProcAddress(kernel, "GetProcessHeap"));
    const auto heapAlloc = reinterpret_cast<Address>(GetProcAddress(kernel, "HeapAlloc"));
    if (getProcessHeap == 0 || heapAlloc == 0) {
        return 0;
    }
    const auto stub = reinterpret_cast<Address>(VirtualAllocEx(process, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == 0) {
        return 0;
    }
    const Address resultAddress = stub + 0x200;
    std::vector<std::uint8_t> code{
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB8
    };
    Append(code, getProcessHeap);
    code.insert(code.end(), {0xFF, 0xD0, 0x48, 0x89, 0xC1, 0x33, 0xD2, 0x41, 0xB8});
    Append(code, size);
    code.insert(code.end(), {0x48, 0xB8});
    Append(code, heapAlloc);
    code.insert(code.end(), {0xFF, 0xD0, 0x48, 0xA3});
    Append(code, resultAddress);
    code.insert(code.end(), {0x48, 0x83, 0xC4, 0x28, 0xC3});
    Address allocation = 0;
    if (WriteMemory(process, stub, code.data(), code.size())) {
        HANDLE thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(stub), nullptr, 0, nullptr);
        if (thread != nullptr) {
            if (WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0) {
                ReadMemory(process, resultAddress, &allocation, sizeof(allocation));
            }
            CloseHandle(thread);
        }
    }
    VirtualFreeEx(process, reinterpret_cast<void*>(stub), 0, MEM_RELEASE);
    return allocation;
}

bool WriteRemoteString(HANDLE process, Address address, const std::string& text) {
    std::array<std::uint8_t, 32> object{};
    const std::uint64_t length = text.size();
    if (length <= 15) {
        std::memcpy(object.data(), text.data(), text.size());
        const std::uint64_t capacity = 15;
        std::memcpy(object.data() + 24, &capacity, sizeof(capacity));
    } else {
        const Address allocation = AllocateTargetHeap(process, static_cast<std::uint32_t>(length + 1));
        if (allocation == 0) {
            return false;
        }
        std::vector<char> content(text.begin(), text.end());
        content.push_back('\0');
        if (!WriteMemory(process, allocation, content.data(), content.size())) {
            return false;
        }
        std::memcpy(object.data(), &allocation, sizeof(allocation));
        std::memcpy(object.data() + 24, &length, sizeof(length));
    }
    std::memcpy(object.data() + 16, &length, sizeof(length));
    return WriteMemory(process, address, object);
}

HANDLE StartLoader(const std::filesystem::path& loader, DWORD& processId) {
    std::wstring command = Quote(loader.wstring());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION information{};
    const auto directory = loader.parent_path().wstring();
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr, directory.c_str(), &startup, &information)) {
        return nullptr;
    }
    CloseHandle(information.hThread);
    processId = information.dwProcessId;
    return information.hProcess;
}

}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    std::cout << "Revolex C++ loader patcher\n";
    if (!IsElevated()) {
        std::cout << "[*] Requesting administrator privileges\n";
        return Elevate(argc, argv) ? 0 : 1;
    }

    const bool attach = argc == 3 && std::wcscmp(argv[1], L"--pid") == 0;
    DWORD processId = 0;
    HANDLE process = nullptr;
    if (attach) {
        processId = std::wcstoul(argv[2], nullptr, 0);
        process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (process == nullptr) {
            std::cerr << "[!] OpenProcess failed: " << ErrorMessage() << '\n';
            return 1;
        }
        std::cout << "[+] Attached to loader, PID " << processId << '\n';
    } else {
        const auto loader = argc > 1
            ? std::filesystem::absolute(argv[1])
            : ExecutablePath().parent_path() / L"qwKJg_6.47.2e5a.exe";
        if (!std::filesystem::exists(loader)) {
            std::cerr << "[!] Loader not found: " << loader << '\n';
            return 1;
        }
        process = StartLoader(loader, processId);
        if (process == nullptr) {
            std::cerr << "[!] CreateProcess failed: " << ErrorMessage() << '\n';
            return 1;
        }
        std::cout << "[+] Loader started, PID " << processId << '\n';
    }

    Address base = 0;
    bool ready = false;
    bool stateDone = false;
    bool shutdownDone = false;
    bool memberDone = false;
    bool expiryDone = false;
    bool coreReported = false;
    bool waitingReported = false;
    bool driverLogged = false;
    bool runProgramDetected = false;
    std::array<bool, revolex::kBranchPatches.size()> branchDone{};
    const auto deadline = Clock::now() + std::chrono::seconds(180);

    while (ProcessRunning(process)) {
        if (base == 0) {
            base = ImageBase(process);
            if (base != 0) {
                std::cout << "[+] Image base " << Hex(base) << '\n';
            }
        }
        if (base == 0) {
            if (Clock::now() > deadline) {
                std::cerr << "[!] Timed out waiting for the loader image base\n";
                CloseHandle(process);
                return 2;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        if (!ready) {
            ready = ImageReady(process, base);
            if (ready) {
                std::cout << "[+] Unpacked image detected\n";
            } else {
                if (Clock::now() > deadline) {
                    std::cerr << "[!] Timed out waiting for the unpacked image\n";
                    CloseHandle(process);
                    return 2;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                continue;
            }
        }

        if (!stateDone) {
            const bool login = WriteMemory(process, base + revolex::kLoginStateRva, revolex::kLoginState);
            const bool readyState = WriteMemory(process, base + revolex::kReadyStateRva, revolex::kReadyState);
            if (login && readyState) {
                stateDone = true;
                std::cout << "[+] Login state patched\n";
            }
        }

        for (std::size_t index = 0; index < revolex::kBranchPatches.size(); ++index) {
            if (branchDone[index]) {
                continue;
            }
            const auto& patch = revolex::kBranchPatches[index];
            std::array<std::uint8_t, 6> current{};
            if (!ReadMemory(process, base + patch.rva, current)) {
                continue;
            }
            if (current == patch.replacement) {
                branchDone[index] = true;
                std::cout << "[=] " << patch.name << " branch already patched\n";
            } else if (current == patch.expected && WriteMemory(process, base + patch.rva, patch.replacement)) {
                branchDone[index] = true;
                std::cout << "[+] " << patch.name << " branch patched\n";
            }
        }

        if (!shutdownDone) {
            std::array<std::uint8_t, 16> current{};
            if (ReadMemory(process, base + revolex::kShutdownRva, current)) {
                if (current == revolex::kShutdownReplacement) {
                    shutdownDone = true;
                    std::cout << "[=] Reboot command already patched\n";
                } else if (current == revolex::kShutdownExpected && WriteMemory(process, base + revolex::kShutdownRva, revolex::kShutdownReplacement)) {
                    shutdownDone = true;
                    std::cout << "[+] Reboot command patched\n";
                }
            }
        }

        if (!memberDone) {
            RemoteString member;
            if (ReadRemoteString(process, base + revolex::kMemberRva, member)) {
                if (member.text == "premium") {
                    memberDone = true;
                } else if (member.text == "Invalid Username or Password!" && WriteRemoteString(process, base + revolex::kMemberRva, "premium")) {
                    memberDone = true;
                    std::cout << "[+] Membership text patched\n";
                }
            }
        }

        if (!expiryDone) {
            RemoteString expiry;
            if (ReadRemoteString(process, base + revolex::kExpiryRva, expiry)) {
                if (expiry.text == "27.12.2049 05:43:29 (23 Year)") {
                    expiryDone = true;
                } else if (expiry.text == "Invalid Username or Password!" && WriteRemoteString(process, base + revolex::kExpiryRva, "27.12.2049 05:43:29 (23 Year)")) {
                    expiryDone = true;
                    std::cout << "[+] Expiry text patched\n";
                }
            }
        }

        const bool branchesComplete = std::all_of(branchDone.begin(), branchDone.end(), [](bool value) { return value; });
        if (!coreReported && stateDone && shutdownDone && branchesComplete) {
            coreReported = true;
            std::cout << "[+] Core patches applied; Premium, Main and Keybind unlocked\n";
            std::cout << "[*] Log in, run the program, then use the unlocked features\n";
        }
        if (!coreReported && Clock::now() > deadline) {
            std::cerr << "[!] Patch timeout:";
            if (!stateDone) std::cerr << " login";
            if (!shutdownDone) std::cerr << " reboot-command";
            for (std::size_t index = 0; index < branchDone.size(); ++index) {
                if (!branchDone[index]) std::cerr << ' ' << revolex::kBranchPatches[index].name;
            }
            std::cerr << '\n';
            CloseHandle(process);
            return 2;
        }
        if (coreReported) {
            if (!waitingReported) {
                waitingReported = true;
                std::cout << "[*] Waiting for Run Program and the ROGMS driver\n";
            }
            const bool driverRunning = DriverRunning();
            if (driverRunning && !driverLogged) {
                driverLogged = true;
                std::cout << "[+] ROGMS driver is running\n";
            }
            if (driverRunning && RunProgramDetected(process, base)) {
                runProgramDetected = true;
                std::cout << "[+] Run Program state detected\n";
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(coreReported ? 250 : 10));
    }

    const bool success = coreReported && runProgramDetected;
    if (success) {
        std::cout << "[+] Patches and driver verified; closing patcher\n";
    } else if (coreReported) {
        std::cerr << "[!] Loader exited before Run Program and the driver were detected\n";
    } else {
        std::cerr << "[!] Loader exited before all core patches were applied\n";
    }
    CloseHandle(process);
    return success ? 0 : 1;
}
