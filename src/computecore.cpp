#include <bitset>
#include <string>
#include <vector>
#include <filesystem>

#include <Windows.h>
#include <computecore.h>

static HMODULE g_hComputenetwork;

// Hook up all apis used by wslservice.exe in computecore.dll.
#define HookApis()  \
    HookApi(HcsCloseComputeSystem); \
    HookApi(HcsCloseOperation); \
    HookApi(HcsCreateComputeSystem); \
    HookApi(HcsCreateOperation); \
    HookApi(HcsGetComputeSystemProperties); \
    HookApi(HcsGetServiceProperties); \
    HookApi(HcsGrantVmAccess); \
    HookApi(HcsModifyComputeSystem); \
    HookApi(HcsOpenComputeSystem); \
    HookApi(HcsRevokeVmAccess); \
    HookApi(HcsSetComputeSystemCallback); \
    HookApi(HcsStartComputeSystem); \
    HookApi(HcsTerminateComputeSystem); \
    HookApi(HcsWaitForOperationResult); \

#define HookApi(api) \
    decltype(&api) g_##api;

    HookApis()

#undef HookApi

// Helper function to replace substring.
static void Replace(std::wstring& str, const std::wstring& from, const std::wstring& to) {
    auto start_pos = str.find(from);
    if (start_pos != std::string::npos) {
        str.replace(start_pos, from.length(), to);
    }
}

// Helper function to get all logic processors cross all cpu groups.
static uint32_t GetLogicCores()
{
    // GetLogicalProcessorInformationEx should return false, and GetLastError() should return ERROR_INSUFFICIENT_BUFFER
    DWORD length = 0;
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return 0;
    }

    // Get the processor information.
    auto pBuffer = std::unique_ptr<uint8_t, decltype(&free)>((uint8_t*)malloc(length), free);
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)pBuffer.get(), &length)) {
        return 0;
    }

    // Enumrate all processors.
    auto totalLogicProcessors = 0u;
    auto pCurrent = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)nullptr;
    for (auto offset = 0u; offset < length; offset += pCurrent->Size) {
        pCurrent = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)(pBuffer.get() + offset);
        for (auto i = 0u; i < pCurrent->Processor.GroupCount; ++i) {
            totalLogicProcessors += (uint32_t)std::bitset<sizeof(pCurrent->Processor.GroupMask[i].Mask) * 8>{pCurrent->Processor.GroupMask[i].Mask}.count();
        }
    }
    return totalLogicProcessors;
}

extern "C" {

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            // Get system folder, should be c:\\windows\\system32.
            auto len = GetSystemDirectoryA(nullptr, 0);
            if (!len) {
                return false;
            }

            std::vector<char> path;
            path.resize(len);
            if (!GetSystemDirectoryA(path.data(), (UINT)path.size())) {
                return false;
            }

            // Get computecore.dll path, assume it should be under c:\\windows\\system32\\computecore.dll.
            auto systemPath = std::filesystem::path{ path.data() } / "computecore.dll";
            if (!(g_hComputenetwork = LoadLibraryA(systemPath.string().c_str()))) {
                return false;
            }

#define HookApi(api) \
            if (!(g_##api = (decltype(&api))GetProcAddress(g_hComputenetwork, #api))) { \
                return false; \
            }

            HookApis()

#undef HookApi
        }
        break;


        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        if (g_hComputenetwork) {
            FreeLibrary(g_hComputenetwork);
        }
        break;
    }
    return TRUE;
}

#pragma comment(linker, "/export:HcsCloseComputeSystem")
void
WINAPI
HcsCloseComputeSystem(
    _In_ _Post_invalid_ HCS_SYSTEM computeSystem
)
{
    return g_HcsCloseComputeSystem(computeSystem);
}

#pragma comment(linker, "/export:HcsCloseOperation")
void
WINAPI
HcsCloseOperation(
    _In_ HCS_OPERATION operation
)
{
    return g_HcsCloseOperation(operation);
}

#pragma comment(linker, "/export:HcsCreateComputeSystem")
HRESULT
WINAPI
HcsCreateComputeSystem(
    _In_ PCWSTR id,
    _In_ PCWSTR configuration,
    _In_ HCS_OPERATION operation,
    _In_opt_ const SECURITY_DESCRIPTOR* securityDescriptor,
    _Out_ HCS_SYSTEM* computeSystem
)
{
    // GetSystemInfo() only returns the number of cores in the current cpu group.
    // In windows, the max number of cores in a single cpu group is 64. So the number
    // of dwNumberOfProcessors in SYSTEM_INFO won't bigger than 64. For this case, we
    // invoke GetLogicCores() to get the total cpu cores crossing all cpu groups.
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);

    auto logicCores = GetLogicCores();
    if (logicCores > 64 && sysInfo.dwNumberOfProcessors < logicCores)
    {
        auto config = std::wstring{ configuration };
        Replace(config, std::format(L"nr_cpus={}", sysInfo.dwNumberOfProcessors), std::format(L"nr_cpus={}", logicCores));
        Replace(config, std::format(L"\"Count\":{}", sysInfo.dwNumberOfProcessors), std::format(L"\"Count\":{}", logicCores));
        return g_HcsCreateComputeSystem(id, config.c_str(), operation, securityDescriptor, computeSystem);
    }
    else
    {
        return g_HcsCreateComputeSystem(id, configuration, operation, securityDescriptor, computeSystem);
    }
}

#pragma comment(linker, "/export:HcsCreateOperation")
HCS_OPERATION
WINAPI
HcsCreateOperation(
    _In_opt_ const void* context,
    _In_opt_ HCS_OPERATION_COMPLETION callback
)
{
    return g_HcsCreateOperation(context, callback);
}

#pragma comment(linker, "/export:HcsGetComputeSystemProperties")
HRESULT
WINAPI
HcsGetComputeSystemProperties(
    _In_ HCS_SYSTEM computeSystem,
    _In_ HCS_OPERATION operation,
    _In_opt_ PCWSTR propertyQuery
)
{
    return g_HcsGetComputeSystemProperties(computeSystem, operation, propertyQuery);
}

#pragma comment(linker, "/export:HcsGetServiceProperties")
HRESULT
WINAPI
HcsGetServiceProperties(
    _In_opt_ PCWSTR propertyQuery,
    _Outptr_ PWSTR* result
)
{
    return g_HcsGetServiceProperties(propertyQuery, result);
}

#pragma comment(linker, "/export:HcsGrantVmAccess")
HRESULT
WINAPI
HcsGrantVmAccess(
    _In_ PCWSTR vmId,
    _In_ PCWSTR filePath
)
{
    return g_HcsGrantVmAccess(vmId, filePath);
}

#pragma comment(linker, "/export:HcsModifyComputeSystem")
HRESULT
WINAPI
HcsModifyComputeSystem(
    _In_ HCS_SYSTEM computeSystem,
    _In_ HCS_OPERATION operation,
    _In_ PCWSTR configuration,
    _In_opt_ HANDLE identity
)
{
    return g_HcsModifyComputeSystem(computeSystem, operation, configuration, identity);
}

#pragma comment(linker, "/export:HcsOpenComputeSystem")
HRESULT
WINAPI
HcsOpenComputeSystem(
    _In_ PCWSTR id,
    _In_ DWORD requestedAccess,
    _Out_ HCS_SYSTEM* computeSystem
)
{
    return g_HcsOpenComputeSystem(id, requestedAccess, computeSystem);
}

#pragma comment(linker, "/export:HcsRevokeVmAccess")
HRESULT
WINAPI
HcsRevokeVmAccess(
    _In_ PCWSTR vmId,
    _In_ PCWSTR filePath
)
{
    return g_HcsRevokeVmAccess(vmId, filePath);
}

#pragma comment(linker, "/export:HcsSetComputeSystemCallback")
HRESULT
WINAPI
HcsSetComputeSystemCallback(
    _In_ HCS_SYSTEM computeSystem,
    _In_ HCS_EVENT_OPTIONS callbackOptions,
    _In_opt_ const void* context,
    _In_ HCS_EVENT_CALLBACK callback
)
{
    return g_HcsSetComputeSystemCallback(computeSystem, callbackOptions, context, callback);
}

#pragma comment(linker, "/export:HcsStartComputeSystem")
HRESULT
WINAPI
HcsStartComputeSystem(
    _In_ HCS_SYSTEM computeSystem,
    _In_ HCS_OPERATION operation,
    _In_opt_ PCWSTR options
)
{
    return g_HcsStartComputeSystem(computeSystem, operation, options);
}

#pragma comment(linker, "/export:HcsTerminateComputeSystem")
HRESULT
WINAPI
HcsTerminateComputeSystem(
    _In_ HCS_SYSTEM computeSystem,
    _In_ HCS_OPERATION operation,
    _In_opt_ PCWSTR options
)
{
    return g_HcsTerminateComputeSystem(computeSystem, operation, options);
}

#pragma comment(linker, "/export:HcsWaitForOperationResult")
HRESULT
WINAPI
HcsWaitForOperationResult(
    _In_ HCS_OPERATION operation,
    _In_ DWORD timeoutMs,
    _Outptr_opt_ PWSTR* resultDocument
)
{
    return g_HcsWaitForOperationResult(operation, timeoutMs, resultDocument);
}

}
