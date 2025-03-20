#include <Windows.h>
#include <Iphlpapi.h>
#include <Assert.h>
#include <iostream>
#include <tchar.h>
#include <intrin.h>
#include <vector>
#include <string>

// For fetching the Graphics Card Info
#pragma comment(lib, "dxgi.lib")
#include <dxgi.h>

// For fetching the Memory Info
#include <Psapi.h>

// For fetching the MAC address
#pragma comment(lib, "iphlpapi.lib")

// For fetching the BIOS Serial Number
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

std::string wstringToString(const std::wstring& wstr) // wstring to string conversion
{
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}


std::vector<std::string> getGraphicsCardInfo()
{
    std::vector<std::string> vGraphicsCards;
    IDXGIFactory* pFactory;
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);

    if (FAILED(hr))
    {
        return vGraphicsCards;
    }

    for (UINT i = 0; ; ++i)
    {
        IDXGIAdapter* pAdapter;
        if (pFactory->EnumAdapters(i, &pAdapter) == DXGI_ERROR_NOT_FOUND)
        {
            break; // No more adapters to enumerate
        }

        // Here we get the device description only
        DXGI_ADAPTER_DESC AdapterDesc;
        pAdapter->GetDesc(&AdapterDesc);
        std::wstring sCardName(AdapterDesc.Description);

        std::string strCardString = wstringToString(sCardName); // Convert to string updated.

        vGraphicsCards.push_back(strCardString);
        pAdapter->Release();
    }

    if (pFactory)
    {
        pFactory->Release();
    }

    return vGraphicsCards;
}

DWORDLONG getTotalSystemMemory()
{
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    return statex.ullTotalPhys / (1024 * 1024);
}


std::string getMACaddress()
{
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        std::cout << "Error allocating memory needed to call GetAdaptersinfo" << std::endl;
        return ""; // it is safe to call free(NULL)
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            std::cout << "Error allocating memory needed to call GetAdaptersinfo" << std::endl;
            return "";
        }
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        char buffer[18];
        sprintf_s(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X",
            pAdapterInfo->Address[0], pAdapterInfo->Address[1],
            pAdapterInfo->Address[2], pAdapterInfo->Address[3],
            pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
        free(pAdapterInfo);
        return std::string(buffer);
    } else {
        free(pAdapterInfo);
        return "";
    }
}

std::string getBiosSerialNumber() {
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        std::cout << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return "";                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres))
    {
        std::cout << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return "";                    // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        std::cout << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return "";                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices *pSvc = NULL;

    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        std::cout << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return "";                // Program has failed.
    }

    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities
    );

    if (FAILED(hres))
    {
        std::cout << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_BIOS"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        std::cout << "Query for operating system name failed. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";         // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    std::string serial;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn)
            break;

        VARIANT vtProp;
        hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        serial = _com_util::ConvertBSTRToString(vtProp.bstrVal);

        VariantClear(&vtProp);
        pclsObj->Release();
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return serial;
}

int main()
{
    //First part gets the HDD informations
    std::cout << "HWID information" << std::endl;
    TCHAR volumeName[MAX_PATH + 1] = { 0 };
    TCHAR fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;
    if (GetVolumeInformation(
        _T("C:\\"),
        volumeName,
        ARRAYSIZE(volumeName),
        &serialNumber,
        &maxComponentLen,
        &fileSystemFlags,
        fileSystemName,
        ARRAYSIZE(fileSystemName)))
    {
        std::cout << "Volume Name: " << volumeName << std::endl;
        std::cout << "HDD Serial: " << serialNumber << std::endl;
        std::cout << "File System Type: " << fileSystemName << std::endl;
        std::cout << "Max Component Length: " << maxComponentLen << std::endl;
    }

    //Second part gets the computer name
    TCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerName(
        computerName,
        &size))
    {
        std::cout << "Computer Name: " << computerName << std::endl;
    }

    //Third part gets the CPU Hash
    int cpuinfo[4] = { 0, 0, 0, 0 }; //EAX, EBX, ECX, EDX
    __cpuid(cpuinfo, 0);
    char32_t hash = 0;
    char16_t* ptr = (char16_t*)(&cpuinfo[0]);
    for (char32_t i = 0; i < 8; i++)
        hash += ptr[i];
    std::cout << "CPU Hash: " << static_cast<std::uint32_t>(hash) << std::endl;

    //Fourth part gets the GPU information
    std::vector<std::string> graphicsCards = getGraphicsCardInfo();
    for (const auto& card : graphicsCards)
    {
        std::cout << "Graphics Card: " << card << std::endl;
    }

    //Fifth part gets the Total System Memory
    DWORDLONG totalMemoryMB = getTotalSystemMemory();
    std::cout << "Total System Memory: " << totalMemoryMB << " MB" << std::endl;


    //Sixth part gets the MAC address
    std::string macAddress = getMACaddress();
    std::cout << "MAC Address: " << macAddress << std::endl;

    //Seventh part gets the BIOS Serial Number
    std::string biosSerial = getBiosSerialNumber();
    std::cout << "BIOS Serial: " << biosSerial << std::endl;

    system("pause");
    return(0);
}
