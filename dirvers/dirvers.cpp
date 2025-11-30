// drivers.cpp
//
// Утилита:
//  - список драйверов (SERVICE_DRIVER)
//  - список обычных сервисов (SERVICE_WIN32)
//  - список загруженных модулей ядра через NtQuerySystemInformation(SystemModuleInformation)
//  - minifilters (по реестру HKLM\SYSTEM\CCS\Services\...\Instances)
//  - поиск по имени (--search / -s)
//  - сохранение вывода в файл (--out / -o)
//  - ключ --all-drivers: показывать все драйверы (не только активные)
//  - вывод PID, учётной записи службы (lpServiceStartName)
//  - вывод SID процесса (в SDDL) и Protection Level (как в Process Hacker, упрощённо)
//
// Компиляция (Developer Command Prompt for VS 2022, x64/ARM64):
//   cl /W4 /EHsc drivers.cpp /link Advapi32.lib Version.lib
//
// Примеры:
//   drivers.exe --all
//   drivers.exe --drivers --modules --search ntdll
//   drivers.exe --drivers --all-drivers
//   drivers.exe --all --out drivers_report.txt

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsvc.h>
#include <winver.h>
#include <winternl.h>
#include <sddl.h>
#include <io.h>
#include <fcntl.h>

#include <cstdarg>
#include <vector>
#include <string>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Version.lib")

// ----------------- Глобалы для логирования --------------------

static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;
static bool   g_logEnabled = false;

// простенькая функция wide->utf8
std::vector<char> WideToUtf8(const wchar_t* s, int len)
{
    std::vector<char> out;
    if (!s || len <= 0)
        return out;

    int needed = WideCharToMultiByte(CP_UTF8, 0, s, len, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return out;

    out.resize(needed);
    WideCharToMultiByte(CP_UTF8, 0, s, len, out.data(), needed, nullptr, nullptr);
    return out;
}

// Универсальный Print: и в консоль, и (опционально) в файл UTF-8
void Print(const wchar_t* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vwprintf(fmt, args);
    va_end(args);

    if (g_logEnabled && g_hLogFile != INVALID_HANDLE_VALUE)
    {
        va_list args2;
        va_start(args2, fmt);
        int len = _vscwprintf(fmt, args2);
        va_end(args2);

        if (len > 0)
        {
            std::wstring buf(len, L'\0');

            va_list args3;
            va_start(args3, fmt);
            _vsnwprintf_s(&buf[0], buf.size() + 1, _TRUNCATE, fmt, args3);
            va_end(args3);

            auto utf8 = WideToUtf8(buf.c_str(), (int)buf.size());
            if (!utf8.empty())
            {
                DWORD written = 0;
                WriteFile(g_hLogFile, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
            }
        }
    }
}

// ----------------- Общие утилиты --------------------

std::wstring ToLower(const std::wstring& s)
{
    std::wstring r = s;
    for (auto& ch : r)
        ch = (wchar_t)towlower(ch);
    return r;
}

bool ContainsNoCase(const std::wstring& text, const std::wstring& needle)
{
    if (needle.empty()) return true;
    auto ltext = ToLower(text);
    auto lneedle = ToLower(needle);
    return ltext.find(lneedle) != std::wstring::npos;
}

std::wstring ExpandPath(const std::wstring& rawPath)
{
    if (rawPath.empty()) return L"";

    std::wstring expanded = rawPath;

    // 1) ExpandEnvironmentStrings
    DWORD needed = ExpandEnvironmentStringsW(expanded.c_str(), nullptr, 0);
    if (needed != 0)
    {
        std::wstring tmp(needed, L'\0');
        if (ExpandEnvironmentStringsW(expanded.c_str(), &tmp[0], needed))
        {
            if (!tmp.empty() && tmp.back() == L'\0')
                tmp.pop_back();
            expanded = tmp;
        }
    }

    // 2) \SystemRoot\... -> C:\Windows\...
    if (expanded.rfind(L"\\SystemRoot", 0) == 0)
    {
        wchar_t winDir[MAX_PATH] = {};
        if (GetWindowsDirectoryW(winDir, MAX_PATH))
        {
            std::wstring winPath = winDir;
            if (!winPath.empty() && (winPath.back() == L'\\' || winPath.back() == L'/'))
                winPath.pop_back();

            expanded = winPath + expanded.substr(wcslen(L"\\SystemRoot"));
        }
    }
    else if (expanded.rfind(L"system32", 0) == 0 ||
        expanded.rfind(L"System32", 0) == 0)
    {
        wchar_t winDir[MAX_PATH] = {};
        if (GetWindowsDirectoryW(winDir, MAX_PATH))
        {
            std::wstring winPath = winDir;
            if (!winPath.empty() && winPath.back() != L'\\')
                winPath += L"\\";
            expanded = winPath + expanded;
        }
    }

    return expanded;
}

std::wstring StartTypeToString(DWORD startType)
{
    switch (startType)
    {
    case SERVICE_BOOT_START:   return L"BOOT_START";
    case SERVICE_SYSTEM_START: return L"SYSTEM_START";
    case SERVICE_AUTO_START:   return L"AUTO_START";
    case SERVICE_DEMAND_START: return L"DEMAND_START";
    case SERVICE_DISABLED:     return L"DISABLED";
    default:                   return L"UNKNOWN";
    }
}

std::wstring ServiceTypeToString(DWORD type)
{
    switch (type)
    {
    case SERVICE_KERNEL_DRIVER:      return L"KERNEL_DRIVER";
    case SERVICE_FILE_SYSTEM_DRIVER: return L"FILE_SYSTEM_DRIVER";
    case SERVICE_RECOGNIZER_DRIVER:  return L"RECOGNIZER_DRIVER";
    case SERVICE_WIN32_OWN_PROCESS:  return L"WIN32_OWN_PROCESS";
    case SERVICE_WIN32_SHARE_PROCESS:return L"WIN32_SHARE_PROCESS";
    default:                         return L"OTHER/UNKNOWN";
    }
}

std::wstring StateToString(DWORD state)
{
    switch (state)
    {
    case SERVICE_STOPPED:          return L"STOPPED";
    case SERVICE_START_PENDING:    return L"START_PENDING";
    case SERVICE_STOP_PENDING:     return L"STOP_PENDING";
    case SERVICE_RUNNING:          return L"RUNNING";
    case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return L"PAUSE_PENDING";
    case SERVICE_PAUSED:           return L"PAUSED";
    default:                       return L"UNKNOWN";
    }
}

// ----------------- Protection Level / SID по PID --------------------

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// В новых SDK может быть уже определено, но на всякий случай:
#ifndef ProcessProtectionInformation
#define ProcessProtectionInformation static_cast<PROCESSINFOCLASS>(61)
#endif

typedef NTSTATUS(NTAPI* PNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );


// Расшифровка ProtectionLevel в человекочитаемый вид
std::wstring DecodeProtectionLevel(ULONG prot)
{
    if (prot == 0)
        return L"None";

    BYTE level = (BYTE)prot;
    BYTE type = level & 0x7;        // низшие 3 бита
    BYTE signer = (level >> 4) & 0xF; // биты 4..7

    const wchar_t* typeStr = L"UnknownType";
    switch (type)
    {
    case 0: typeStr = L"None";            break;
    case 1: typeStr = L"ProtectedLight";  break;
    case 2: typeStr = L"Protected";       break;
    default: break;
    }

    const wchar_t* signerStr = L"UnknownSigner";
    switch (signer)
    {
    case 0: signerStr = L"None";      break;
    case 1: signerStr = L"Authenticode"; break;
    case 2: signerStr = L"CodeGen";   break;
    case 3: signerStr = L"Antimalware"; break;
    case 4: signerStr = L"Lsa";       break;
    case 5: signerStr = L"Windows";   break;
    case 6: signerStr = L"WinTcb";    break;
    case 7: signerStr = L"WinSystem"; break;
    default: break;
    }

    wchar_t buf[128];
    swprintf_s(buf, L"%s / %s (0x%02X)", typeStr, signerStr, level);
    return buf;
}

// Получение SID (в SDDL) и ProtectionLevel по PID
bool GetProcessSidAndProtection(
    DWORD pid,
    std::wstring& outSidSddl,
    std::wstring& outProtStr)
{
    outSidSddl.clear();
    outProtStr.clear();

    if (pid == 0)
    {
        outSidSddl = L"<none>";
        outProtStr = L"<kernel/system>";
        return true;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        outSidSddl = L"<no access>";
        outProtStr = L"<no access>";
        return false;
    }

    // --- Protection Level ---
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll)
    {
        auto pNtQueryInformationProcess =
            (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pNtQueryInformationProcess)
        {
            PROCESS_PROTECTION_LEVEL_INFORMATION pli = {};
            NTSTATUS st = pNtQueryInformationProcess(
                hProc,
                ProcessProtectionInformation,
                &pli,
                sizeof(pli),
                nullptr);

            if (NT_SUCCESS(st))
            {
                outProtStr = DecodeProtectionLevel(pli.ProtectionLevel);
            }
            else
            {
                outProtStr = L"(NtQueryInformationProcess failed)";
            }
        }
        else
        {
            outProtStr = L"(NtQueryInformationProcess not found)";
        }
    }
    else
    {
        outProtStr = L"(ntdll not found)";
    }

    // --- SID (TokenUser) в SDDL ---
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
    {
        // Нет доступа к токену (PPL и т.п.) — защита
        if (outSidSddl.empty())
            outSidSddl = L"<no access>";
        CloseHandle(hProc);
        return false;
    }

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    if (needed == 0)
    {
        outSidSddl = L"(TokenUser size = 0)";
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), needed, &needed))
    {
        outSidSddl = L"(GetTokenInformation failed)";
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    TOKEN_USER* pUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    PSID sid = pUser->User.Sid;

    LPWSTR sddl = nullptr;
    if (ConvertSidToStringSidW(sid, &sddl))
    {
        outSidSddl = sddl;
        LocalFree(sddl);
    }
    else
    {
        outSidSddl = L"(ConvertSidToStringSidW failed)";
    }

    CloseHandle(hToken);
    CloseHandle(hProc);
    return true;
}

// Чтение версионных строк (FileVersion, FileDescription, CompanyName)
bool GetFileVersionStrings(
    const std::wstring& filePath,
    std::wstring& outVersion,
    std::wstring& outDescription,
    std::wstring& outCompany)
{
    outVersion.clear();
    outDescription.clear();
    outCompany.clear();

    if (filePath.empty())
        return false;

    DWORD handle = 0;
    DWORD verSize = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
    if (verSize == 0)
        return false;

    std::vector<BYTE> buffer(verSize);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, verSize, buffer.data()))
        return false;

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    };

    LANGANDCODEPAGE* translations = nullptr;
    UINT translationsSize = 0;

    if (!VerQueryValueW(
        buffer.data(),
        L"\\VarFileInfo\\Translation",
        reinterpret_cast<LPVOID*>(&translations),
        &translationsSize) ||
        translationsSize < sizeof(LANGANDCODEPAGE))
    {
        static LANGANDCODEPAGE defaultTrans{ 0x0409, 0x04B0 }; // en-US, Unicode
        translations = &defaultTrans;
        translationsSize = sizeof(defaultTrans);
    }

    WCHAR subBlock[64];

    auto QueryString = [&](const wchar_t* name, std::wstring& out) -> void
        {
            swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s",
                translations[0].wLanguage,
                translations[0].wCodePage,
                name);

            LPVOID value = nullptr;
            UINT   size = 0;
            if (VerQueryValueW(buffer.data(), subBlock, &value, &size) && value && size > 0)
            {
                out.assign(static_cast<wchar_t*>(value), size);
            }
        };

    QueryString(L"FileVersion", outVersion);
    QueryString(L"FileDescription", outDescription);
    QueryString(L"CompanyName", outCompany);

    return !(outVersion.empty() && outDescription.empty() && outCompany.empty());
}

// ----------------- Список драйверов (SERVICE_DRIVER) --------------------

struct DriverServiceInfo
{
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring imagePathRaw;
    std::wstring imagePathExpanded;
    DWORD         startType = 0;
    DWORD         serviceType = 0;
    DWORD         currentState = 0;
    DWORD         processId = 0;
    std::wstring  serviceAccount;   // учётка службы (lpServiceStartName)

    std::wstring fileVersion;
    std::wstring fileDescription;
    std::wstring companyName;
};

std::vector<DriverServiceInfo> EnumerateDriverServices(bool onlyRunning)
{
    std::vector<DriverServiceInfo> result;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
    {
        Print(L"OpenSCManagerW (drivers) failed, error=%lu\n", GetLastError());
        return result;
    }

    DWORD bytesNeeded = 0;
    DWORD servicesCount = 0;
    DWORD resumeHandle = 0;

    DWORD serviceState = onlyRunning ? SERVICE_ACTIVE : SERVICE_STATE_ALL;

    EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_DRIVER,
        serviceState,
        nullptr,
        0,
        &bytesNeeded,
        &servicesCount,
        &resumeHandle,
        nullptr);

    if (GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0)
    {
        Print(L"EnumServicesStatusExW (drivers probe) failed, error=%lu\n", GetLastError());
        CloseServiceHandle(scm);
        return result;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    resumeHandle = 0;

    if (!EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_DRIVER,
        serviceState,
        buffer.data(),
        (DWORD)buffer.size(),
        &bytesNeeded,
        &servicesCount,
        &resumeHandle,
        nullptr))
    {
        Print(L"EnumServicesStatusExW (drivers real) failed, error=%lu\n", GetLastError());
        CloseServiceHandle(scm);
        return result;
    }

    auto entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

    for (DWORD i = 0; i < servicesCount; ++i)
    {
        const auto& e = entries[i];

        DriverServiceInfo info;
        info.serviceName = e.lpServiceName ? e.lpServiceName : L"";
        info.displayName = e.lpDisplayName ? e.lpDisplayName : L"";
        info.currentState = e.ServiceStatusProcess.dwCurrentState;
        info.processId = e.ServiceStatusProcess.dwProcessId;

        SC_HANDLE svc = OpenServiceW(scm, e.lpServiceName, SERVICE_QUERY_CONFIG);
        if (svc)
        {
            DWORD cfgBytesNeeded = 0;
            QueryServiceConfigW(svc, nullptr, 0, &cfgBytesNeeded);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cfgBytesNeeded > 0)
            {
                std::vector<BYTE> cfgBuf(cfgBytesNeeded);
                auto cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());

                if (QueryServiceConfigW(svc, cfg, cfgBytesNeeded, &cfgBytesNeeded))
                {
                    if (cfg->lpBinaryPathName)
                        info.imagePathRaw = cfg->lpBinaryPathName;
                    info.startType = cfg->dwStartType;
                    info.serviceType = cfg->dwServiceType;

                    info.imagePathExpanded = ExpandPath(info.imagePathRaw);

                    if (cfg->lpServiceStartName)
                        info.serviceAccount = cfg->lpServiceStartName;
                }
            }

            CloseServiceHandle(svc);
        }

        if (!info.imagePathExpanded.empty())
        {
            GetFileVersionStrings(info.imagePathExpanded,
                info.fileVersion,
                info.fileDescription,
                info.companyName);
        }

        result.push_back(std::move(info));
    }

    CloseServiceHandle(scm);
    return result;
}

void PrintDriverServices(const std::vector<DriverServiceInfo>& list,
    const std::wstring& filter,
    bool onlyRunning,
    bool allDriversFlag)
{
    Print(L"=== ДРАЙВЕРЫ (SERVICE_DRIVER) ===\n");
    Print(L"Всего: %zu (%s)\n\n",
        list.size(),
        onlyRunning && !allDriversFlag ? L"только активные" : L"все состояния");

    for (size_t i = 0; i < list.size(); ++i)
    {
        const auto& d = list[i];

        std::wstring haystack =
            d.serviceName + L" " + d.displayName + L" " + d.imagePathExpanded;

        if (!ContainsNoCase(haystack, filter))
            continue;

        Print(L"[%3zu] %s\n", i, d.serviceName.c_str());

        if (!d.displayName.empty())
            Print(L"    DisplayName:   %s\n", d.displayName.c_str());

        Print(L"    State:         %lu (%s)\n",
            d.currentState, StateToString(d.currentState).c_str());

        Print(L"    Type:          %lu (%s)\n",
            d.serviceType, ServiceTypeToString(d.serviceType).c_str());

        Print(L"    StartType:     %lu (%s)\n",
            d.startType, StartTypeToString(d.startType).c_str());

        Print(L"    PID:           %lu\n", d.processId);
        if (!d.serviceAccount.empty())
            Print(L"    Account:       %s\n", d.serviceAccount.c_str());
        else
            Print(L"    Account:       (нет данных)\n");

        // SID / Protection
        {
            std::wstring sid, prot;
            if (GetProcessSidAndProtection(d.processId, sid, prot))
            {
                Print(L"    SID:           %s\n", sid.c_str());
                Print(L"    Protection:    %s\n", prot.c_str());
            }
            else
            {
                Print(L"    SID:           %s\n", sid.c_str());
                Print(L"    Protection:    %s\n", prot.c_str());
            }
        }

        if (!d.imagePathRaw.empty())
            Print(L"    ImagePath:     %s\n", d.imagePathRaw.c_str());

        if (!d.imagePathExpanded.empty() &&
            _wcsicmp(d.imagePathRaw.c_str(), d.imagePathExpanded.c_str()) != 0)
        {
            Print(L"    ImagePathEx:   %s\n", d.imagePathExpanded.c_str());
        }

        if (!d.fileVersion.empty())
            Print(L"    FileVersion:   %s\n", d.fileVersion.c_str());
        else
            Print(L"    FileVersion:   (нет данных)\n");

        if (!d.fileDescription.empty())
            Print(L"    Description:   %s\n", d.fileDescription.c_str());

        if (!d.companyName.empty())
            Print(L"    Company:       %s\n", d.companyName.c_str());

        Print(L"    Реестр:        HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s\n",
            d.serviceName.c_str());

        // Minifilter-инфо (по реестру)
        HKEY hKey = nullptr;
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\";
        keyPath += d.serviceName;
        keyPath += L"\\Instances";

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
            KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            wchar_t defInstance[256];
            DWORD   siz = sizeof(defInstance);
            DWORD   type = 0;
            if (RegQueryValueExW(hKey, L"DefaultInstance", nullptr,
                &type, (LPBYTE)defInstance, &siz) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ))
            {
                Print(L"    Minifilter:    DefaultInstance = %s\n", defInstance);

                HKEY hInst = nullptr;
                if (RegOpenKeyExW(hKey, defInstance, 0, KEY_READ, &hInst) == ERROR_SUCCESS)
                {
                    wchar_t altitude[256];
                    DWORD asz = sizeof(altitude);
                    DWORD atype = 0;
                    if (RegQueryValueExW(hInst, L"Altitude", nullptr,
                        &atype, (LPBYTE)altitude, &asz) == ERROR_SUCCESS &&
                        (atype == REG_SZ || atype == REG_EXPAND_SZ))
                    {
                        Print(L"    Altitude:      %s\n", altitude);
                    }
                    RegCloseKey(hInst);
                }
            }
            RegCloseKey(hKey);
        }

        Print(L"\n");
    }

    Print(L"\n");
}

// ----------------- Обычные сервисы (SERVICE_WIN32) --------------------

struct Win32ServiceInfo
{
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring imagePathRaw;
    std::wstring imagePathExpanded;
    DWORD         startType = 0;
    DWORD         serviceType = 0;
    DWORD         currentState = 0;
    DWORD         processId = 0;
    std::wstring  serviceAccount;
};

std::vector<Win32ServiceInfo> EnumerateWin32Services(bool onlyRunning)
{
    std::vector<Win32ServiceInfo> result;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
    {
        Print(L"OpenSCManagerW (services) failed, error=%lu\n", GetLastError());
        return result;
    }

    DWORD bytesNeeded = 0;
    DWORD servicesCount = 0;
    DWORD resumeHandle = 0;

    DWORD serviceState = onlyRunning ? SERVICE_ACTIVE : SERVICE_STATE_ALL;

    EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        serviceState,
        nullptr,
        0,
        &bytesNeeded,
        &servicesCount,
        &resumeHandle,
        nullptr);

    if (GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0)
    {
        Print(L"EnumServicesStatusExW (services probe) failed, error=%lu\n", GetLastError());
        CloseServiceHandle(scm);
        return result;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    resumeHandle = 0;

    if (!EnumServicesStatusExW(
        scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        serviceState,
        buffer.data(),
        (DWORD)buffer.size(),
        &bytesNeeded,
        &servicesCount,
        &resumeHandle,
        nullptr))
    {
        Print(L"EnumServicesStatusExW (services real) failed, error=%lu\n", GetLastError());
        CloseServiceHandle(scm);
        return result;
    }

    auto entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

    for (DWORD i = 0; i < servicesCount; ++i)
    {
        const auto& e = entries[i];

        Win32ServiceInfo info;
        info.serviceName = e.lpServiceName ? e.lpServiceName : L"";
        info.displayName = e.lpDisplayName ? e.lpDisplayName : L"";
        info.currentState = e.ServiceStatusProcess.dwCurrentState;
        info.processId = e.ServiceStatusProcess.dwProcessId;

        SC_HANDLE svc = OpenServiceW(scm, e.lpServiceName, SERVICE_QUERY_CONFIG);
        if (svc)
        {
            DWORD cfgBytesNeeded = 0;
            QueryServiceConfigW(svc, nullptr, 0, &cfgBytesNeeded);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cfgBytesNeeded > 0)
            {
                std::vector<BYTE> cfgBuf(cfgBytesNeeded);
                auto cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());

                if (QueryServiceConfigW(svc, cfg, cfgBytesNeeded, &cfgBytesNeeded))
                {
                    if (cfg->lpBinaryPathName)
                        info.imagePathRaw = cfg->lpBinaryPathName;
                    info.startType = cfg->dwStartType;
                    info.serviceType = cfg->dwServiceType;

                    info.imagePathExpanded = ExpandPath(info.imagePathRaw);

                    if (cfg->lpServiceStartName)
                        info.serviceAccount = cfg->lpServiceStartName;
                }
            }

            CloseServiceHandle(svc);
        }

        result.push_back(std::move(info));
    }

    CloseServiceHandle(scm);
    return result;
}

void PrintWin32Services(const std::vector<Win32ServiceInfo>& list,
    const std::wstring& filter)
{
    Print(L"=== СЕРВИСЫ (SERVICE_WIN32) ===\n");
    Print(L"Всего: %zu (только активные)\n\n", list.size());

    for (size_t i = 0; i < list.size(); ++i)
    {
        const auto& s = list[i];

        std::wstring haystack =
            s.serviceName + L" " + s.displayName + L" " + s.imagePathExpanded;

        if (!ContainsNoCase(haystack, filter))
            continue;

        Print(L"[%3zu] %s\n", i, s.serviceName.c_str());
        if (!s.displayName.empty())
            Print(L"    DisplayName:   %s\n", s.displayName.c_str());

        Print(L"    State:         %lu (%s)\n",
            s.currentState, StateToString(s.currentState).c_str());

        Print(L"    Type:          %lu (%s)\n",
            s.serviceType, ServiceTypeToString(s.serviceType).c_str());

        Print(L"    StartType:     %lu (%s)\n",
            s.startType, StartTypeToString(s.startType).c_str());

        Print(L"    PID:           %lu\n", s.processId);
        if (!s.serviceAccount.empty())
            Print(L"    Account:       %s\n", s.serviceAccount.c_str());
        else
            Print(L"    Account:       (нет данных)\n");

        {
            std::wstring sid, prot;
            if (GetProcessSidAndProtection(s.processId, sid, prot))
            {
                Print(L"    SID:           %s\n", sid.c_str());
                Print(L"    Protection:    %s\n", prot.c_str());
            }
            else
            {
                Print(L"    SID:           %s\n", sid.c_str());
                Print(L"    Protection:    %s\n", prot.c_str());
            }
        }

        if (!s.imagePathRaw.empty())
            Print(L"    ImagePath:     %s\n", s.imagePathRaw.c_str());

        if (!s.imagePathExpanded.empty() &&
            _wcsicmp(s.imagePathRaw.c_str(), s.imagePathExpanded.c_str()) != 0)
        {
            Print(L"    ImagePathEx:   %s\n", s.imagePathExpanded.c_str());
        }

        Print(L"\n");
    }

    Print(L"\n");
}

// ----------------- Модули ядра через NtQuerySystemInformation --------------------

typedef enum _MY_SYSTEM_INFORMATION_CLASS {
    MySystemModuleInformation = 11 // SystemModuleInformation
} MY_SYSTEM_INFORMATION_CLASS;

typedef struct _MY_SYSTEM_MODULE_ENTRY
{
    PVOID  Reserved1[2];
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} MY_SYSTEM_MODULE_ENTRY, * PMY_SYSTEM_MODULE_ENTRY;

typedef struct _MY_SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    MY_SYSTEM_MODULE_ENTRY Modules[1];
} MY_SYSTEM_MODULE_INFORMATION, * PMY_SYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
    MY_SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

struct KernelModuleInfo
{
    std::wstring baseName;
    std::wstring fullPath;
    PVOID        baseAddress;
    ULONG        imageSize;
};

std::vector<KernelModuleInfo> EnumerateKernelModules()
{
    std::vector<KernelModuleInfo> result;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        Print(L"GetModuleHandleW(ntdll) failed\n");
        return result;
    }

    auto pNtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!pNtQuerySystemInformation)
    {
        Print(L"GetProcAddress(NtQuerySystemInformation) failed\n");
        return result;
    }

    ULONG size = 0x10000;
    std::vector<BYTE> buffer;
    NTSTATUS status;

    while (true)
    {
        buffer.resize(size);
        ULONG needed = 0;
        status = pNtQuerySystemInformation(
            MySystemModuleInformation,
            buffer.data(),
            size,
            &needed);

        if (NT_SUCCESS(status))
        {
            break;
        }
        else if (status == 0xC0000004L /*STATUS_INFO_LENGTH_MISMATCH*/ && needed > size)
        {
            size = needed + 0x1000;
            continue;
        }
        else
        {
            Print(L"NtQuerySystemInformation(SystemModuleInformation) failed, NTSTATUS=0x%08X\n",
                status);
            return result;
        }
    }

    auto pInfo = reinterpret_cast<PMY_SYSTEM_MODULE_INFORMATION>(buffer.data());
    ULONG count = pInfo->NumberOfModules;

    for (ULONG i = 0; i < count; ++i)
    {
        const auto& m = pInfo->Modules[i];

        std::string ansiPath((const char*)m.FullPathName);
        std::wstring wPath;
        if (!ansiPath.empty())
        {
            int wlen = MultiByteToWideChar(CP_ACP, 0,
                ansiPath.c_str(), -1,
                nullptr, 0);
            if (wlen > 0)
            {
                wPath.resize(wlen - 1);
                MultiByteToWideChar(CP_ACP, 0,
                    ansiPath.c_str(), -1,
                    &wPath[0], wlen);
            }
        }

        std::wstring baseName = L"";
        if (!wPath.empty())
        {
            size_t pos = wPath.find_last_of(L"\\/");
            if (pos == std::wstring::npos)
                baseName = wPath;
            else
                baseName = wPath.substr(pos + 1);
        }

        KernelModuleInfo info;
        info.baseName = baseName;
        info.fullPath = wPath;
        info.baseAddress = m.ImageBase;
        info.imageSize = m.ImageSize;

        result.push_back(std::move(info));
    }

    return result;
}

void PrintKernelModules(const std::vector<KernelModuleInfo>& list,
    const std::wstring& filter)
{
    Print(L"=== МОДУЛИ ЯДРА (NtQuerySystemInformation/SystemModuleInformation) ===\n");
    Print(L"Всего: %zu\n\n", list.size());

    for (size_t i = 0; i < list.size(); ++i)
    {
        const auto& m = list[i];

        std::wstring haystack = m.baseName + L" " + m.fullPath;
        if (!ContainsNoCase(haystack, filter))
            continue;

        Print(L"[%3zu] %s\n", i, m.baseName.c_str());
        Print(L"    BaseAddress:   0x%p\n", m.baseAddress);
        Print(L"    ImageSize:     0x%08X (%u)\n", m.imageSize, m.imageSize);

        if (!m.fullPath.empty())
            Print(L"    FullPath:      %s\n", m.fullPath.c_str());

        Print(L"\n");
    }

    Print(L"\n");
}

// ----------------- main + разбор аргументов --------------------

void PrintUsage()
{
    Print(L"Использование:\n");
    Print(L"  drivers.exe [--drivers] [--services] [--modules] [--all]\n");
    Print(L"             [--all-drivers]\n");
    Print(L"             [--search <substr>] [--out <file>]\n\n");
    Print(L"По умолчанию, если без флагов, эквивалентно --all.\n");
    Print(L"  --drivers       : список драйверов (SERVICE_DRIVER)\n");
    Print(L"  --all-drivers   : показывать все драйверы (не только активные)\n");
    Print(L"  --services      : список обычных сервисов (SERVICE_WIN32)\n");
    Print(L"  --modules       : список модулей ядра (SystemModuleInformation)\n");
    Print(L"  --all           : всё сразу (drivers + services + modules)\n");
    Print(L"  --search, -s    : фильтр по имени/пути\n");
    Print(L"  --out, -o       : сохранить вывод в файл (UTF-8)\n\n");
    Print(L"Примеры:\n");
    Print(L"  drivers.exe --all\n");
    Print(L"  drivers.exe --drivers --modules --search ntoskrnl\n");
    Print(L"  drivers.exe --drivers --all-drivers\n");
    Print(L"  drivers.exe --all --out report.txt\n");
}

int wmain(int argc, wchar_t** argv)
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    bool wantDrivers = false;
    bool wantServices = false;
    bool wantModules = false;
    bool wantAll = false;
    bool allDriversFlag = false;
    std::wstring search;
    std::wstring outFile;

    for (int i = 1; i < argc; ++i)
    {
        const wchar_t* arg = argv[i];

        if (_wcsicmp(arg, L"--drivers") == 0)
            wantDrivers = true;
        else if (_wcsicmp(arg, L"--services") == 0)
            wantServices = true;
        else if (_wcsicmp(arg, L"--modules") == 0)
            wantModules = true;
        else if (_wcsicmp(arg, L"--all") == 0)
            wantAll = true;
        else if (_wcsicmp(arg, L"--all-drivers") == 0)
            allDriversFlag = true;
        else if (_wcsicmp(arg, L"--search") == 0 || _wcsicmp(arg, L"-s") == 0)
        {
            if (i + 1 < argc)
            {
                search = argv[++i];
            }
        }
        else if (_wcsicmp(arg, L"--out") == 0 || _wcsicmp(arg, L"-o") == 0)
        {
            if (i + 1 < argc)
            {
                outFile = argv[++i];
            }
        }
        else if (_wcsicmp(arg, L"--help") == 0 || _wcsicmp(arg, L"-h") == 0)
        {
            PrintUsage();
            return 0;
        }
        else
        {
            Print(L"Неизвестный аргумент: %s\n\n", arg);
            PrintUsage();
            return 1;
        }
    }

    if (!wantDrivers && !wantServices && !wantModules && !wantAll)
        wantAll = true;

    if (wantAll)
    {
        wantDrivers = true;
        wantServices = true;
        wantModules = true;
    }

    // Открываем файл, если указан
    if (!outFile.empty())
    {
        g_hLogFile = CreateFileW(outFile.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (g_hLogFile != INVALID_HANDLE_VALUE)
        {
            g_logEnabled = true;
            const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
            DWORD written = 0;
            WriteFile(g_hLogFile, bom, 3, &written, nullptr);
        }
        else
        {
            Print(L"Не удалось открыть файл %s для записи, error=%lu\n",
                outFile.c_str(), GetLastError());
        }
    }

    Print(L"drivers.exe — утилита перечисления драйверов/сервисов/модулей ядра\n\n");

    if (!search.empty())
        Print(L"Фильтр поиска: \"%s\"\n\n", search.c_str());

    bool onlyRunningDrivers = !allDriversFlag;

    if (wantDrivers)
    {
        auto drivers = EnumerateDriverServices(onlyRunningDrivers);
        PrintDriverServices(drivers, search, onlyRunningDrivers, allDriversFlag);
    }

    if (wantServices)
    {
        auto services = EnumerateWin32Services(true); // только активные
        PrintWin32Services(services, search);
    }

    if (wantModules)
    {
        auto modules = EnumerateKernelModules();
        PrintKernelModules(modules, search);
    }

    if (g_hLogFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }

    return 0;
}
