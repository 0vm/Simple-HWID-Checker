#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>
#include <array>
#include <Windows.h>
#include <Iphlpapi.h>
#include <intrin.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <initguid.h>
#include <dxgi.h>
#include <dxgi1_6.h>
#include <d3d11.h>
#include <ntddscsi.h>
#include <winioctl.h>
#include <atlbase.h>
#include <shlwapi.h>
#include <Wincrypt.h>
#include <sddl.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <winternl.h>
#include <ks.h>
#include <wbemcli.h>

// Define TPM-related structures and functions if not already defined
#ifndef TBS_SUCCESS
#define TBS_SUCCESS                 0
typedef UINT32 TBS_RESULT;
typedef UINT32 TBS_HCONTEXT;
typedef struct TBS_CONTEXT_PARAMS {
    UINT32 version;
    BOOL   asynchronous;
} TBS_CONTEXT_PARAMS;
#define TBS_CONTEXT_VERSION_ONE     1
#define TBS_CONTEXT_VERSION_TWO     2

// TPM Base Service function prototypes
extern "C" {
    __declspec(dllimport) TBS_RESULT __stdcall Tbsi_Context_Create(
        _In_  const TBS_CONTEXT_PARAMS* pContextParams,
        _Out_ TBS_HCONTEXT*             phContext
    );
    
    __declspec(dllimport) TBS_RESULT __stdcall Tbsi_Context_Close(
        _In_ TBS_HCONTEXT hContext
    );
    
    __declspec(dllimport) TBS_RESULT __stdcall Tbsi_GetDeviceInfo(
        _In_  UINT32                      Size,
        _Out_ PVOID                       Information
    );
    
    __declspec(dllimport) TBS_RESULT __stdcall Tbsi_GetRandom(
        _In_  TBS_HCONTEXT                hContext,
        _Out_ BYTE*                       pRgbRandom,
        _In_  UINT32                      cbRandom
    );
    
    __declspec(dllimport) TBS_RESULT __stdcall Tbsi_GetTpmProperty(
        _In_  TBS_HCONTEXT                hContext,
        _In_  UINT32                      PropertyId,
        _In_  UINT32                      PropertySubId,
        _In_  UINT32                      Size,
        _Out_ PBYTE                       PropertyValue
    );
}
#endif

// TPM-related definitions
#define TPM_AVAILABLE 
#define TPM_BASE 0x0
#define TPM_RESULT_COUNT 0x8
#define TPM_ORD_GetRandom 0x46

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

// SMBIOS table access definitions
#define SMBIOS_HARDWARE_SECURITY 0x25
#define SMBIOS_SYSTEM_INFORMATION 0x1
#define SMBIOS_BIOS_INFORMATION 0x0

// IOCTL codes for disk operations
#ifndef IOCTL_STORAGE_QUERY_PROPERTY
#define IOCTL_STORAGE_QUERY_PROPERTY 0x2d1400
#endif

enum class IdType {
    HARDWARE, // Physical hardware identifiers that typically won't change
    SOFTWARE  // Software-based identifiers that can change with reinstalls/resets
};

class HWIDGrabber {
private:
    std::string GetStringFromBytes(const std::vector<BYTE>& bytes) {
        std::stringstream ss;
        for (size_t i = 0; i < bytes.size(); i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
            if (i < bytes.size() - 1) ss << "-";
        }
        return ss.str();
    }

    std::string GetWMIProperty(IWbemClassObject* obj, const wchar_t* property) {
        VARIANT vtProp;
        HRESULT hr = obj->Get(property, 0, &vtProp, 0, 0);
        std::string result;
        
        if (SUCCEEDED(hr)) {
            if (vtProp.vt == VT_BSTR && vtProp.bstrVal != nullptr) {
                _bstr_t bstr_t(vtProp.bstrVal, false);
                result = static_cast<const char*>(bstr_t);
            }
            VariantClear(&vtProp);
        }
        
        return result;
    }

    template<class T>
    void SafeRelease(T** ppT) {
        if (*ppT) {
            (*ppT)->Release();
            *ppT = nullptr;
        }
    }
    
    // More secure hashing using BCrypt (modern Windows crypto API)
    std::string BCryptHashString(const std::string& input) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = 0;
        DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;
        std::string hashStr = "";
        std::stringstream ss;

        // Open algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto Cleanup;
        }

        // Get hash object size
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto Cleanup;
        }

        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        if (NULL == pbHashObject) {
            goto Cleanup;
        }

        // Get hash length
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto Cleanup;
        }

        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (NULL == pbHash) {
            goto Cleanup;
        }

        // Create hash
        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto Cleanup;
        }

        // Hash data
        status = BCryptHashData(hHash, (PUCHAR)input.c_str(), static_cast<ULONG>(input.length()), 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto Cleanup;
        }

        // Finalize hash
        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto Cleanup;
        }

        // Format hash as hex string
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
        }
        hashStr = ss.str();

    Cleanup:
        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
        if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);

        return hashStr;
    }
    
    // Get SMBIOS information directly for more reliable hardware identification
    std::string GetSMBIOSData() {
        DWORD smbiosDataSize = 0;
        std::vector<BYTE> smbiosData;
        std::stringstream result;
        
        // Get size of SMBIOS data
        DWORD smbiosSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
        if (smbiosSize > 0) {
            smbiosData.resize(smbiosSize);
            DWORD bytesRead = GetSystemFirmwareTable('RSMB', 0, smbiosData.data(), smbiosSize);
            
            if (bytesRead > 0) {
                // Raw SMBIOS data fingerprint - harder to spoof than WMI
                result << "SMBIOS Data Signature: " << GetStringFromBytes(std::vector<BYTE>(smbiosData.begin(), smbiosData.begin() + 16)) << std::endl;
                
                // Extract SMBIOS version
                if (smbiosData.size() > 0x08) {
                    result << "SMBIOS Version: " 
                           << static_cast<int>(smbiosData[0x06]) << "." 
                           << static_cast<int>(smbiosData[0x07]) << std::endl;
                }
                
                // Process structures after header
                BYTE* ptr = smbiosData.data() + 8; // Skip header
                BYTE* endPtr = smbiosData.data() + smbiosSize;
                
                while (ptr < endPtr) {
                    BYTE type = *ptr;
                    BYTE length = *(ptr + 1);
                    
                    if (type == 0 && length < 4) break; // End of table
                    
                    if (type == SMBIOS_SYSTEM_INFORMATION && length >= 8) {
                        result << "System Manufacturer: " << (const char*)(ptr + 4) << std::endl;
                        result << "System Product: " << (const char*)(ptr + 5) << std::endl;
                        result << "System Serial: " << (const char*)(ptr + 7) << std::endl;
                    }
                    
                    // Find the string area ending (double NUL)
                    BYTE* strPtr = ptr + length;
                    while (strPtr < endPtr && !(*strPtr == 0 && *(strPtr + 1) == 0)) {
                        strPtr++;
                    }
                    
                    // Move to the next structure
                    ptr = strPtr + 2;
                }
            }
        }
        
        return result.str();
    }
    
    // Get TPM identifier if available - extremely difficult to spoof
    std::string GetTPMInfo() {
        std::stringstream result;
        TBS_CONTEXT_PARAMS contextParams;
        TBS_HCONTEXT hContext = 0;
        UINT32 tpmVersion = 0;
        
        // Initialize the context parameters for TPM 2.0
        contextParams.version = TBS_CONTEXT_VERSION_TWO;
        contextParams.asynchronous = FALSE;
        
        // Attempt to create a context with the TPM Base Services
        HRESULT hr = Tbsi_Context_Create(&contextParams, &hContext);
        if (SUCCEEDED(hr)) {
            // Get TPM version
            hr = Tbsi_GetDeviceInfo(sizeof(UINT32), &tpmVersion);
            if (SUCCEEDED(hr)) {
                result << "TPM Version: " << (tpmVersion == 1 ? "1.2" : "2.0") << std::endl;
                
                // Get TPM properties (2.0 specific)
                if (tpmVersion == 2) {
                    UINT32 tpmProps[2] = { 0 }; // Manufacturer and version info
                    UINT32 propSize = sizeof(tpmProps);
                    
                    hr = Tbsi_GetTpmProperty(hContext, 1, TPM_BASE, propSize, (PBYTE)tpmProps);
                    if (SUCCEEDED(hr)) {
                        result << "TPM Manufacturer: 0x" << std::hex << tpmProps[0] << std::endl;
                        result << "TPM Version: 0x" << std::hex << tpmProps[1] << std::endl;
                    }
                }
                
                // Get a random value from the TPM as a unique identifier that's hardware-bound
                BYTE randomBytes[32] = { 0 };
                hr = Tbsi_GetRandom(hContext, randomBytes, sizeof(randomBytes));
                if (SUCCEEDED(hr)) {
                    std::vector<BYTE> randomVec(randomBytes, randomBytes + sizeof(randomBytes));
                    result << "TPM Random ID: " << GetStringFromBytes(randomVec) << std::endl;
                }
            }
            
            // Close TPM context
            Tbsi_Context_Close(hContext);
        }
        else {
            result << "TPM not available or accessible" << std::endl;
        }
        
        return result.str();
    }

    std::string ExecuteWMICCommand(const std::string& command) {
        std::string result;
        char buffer[128];
        std::string cmd = "wmic " + command + " 2>&1";
        
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) {
            return "Error executing WMIC command";
        }
        
        while (!feof(pipe)) {
            if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                result += buffer;
            }
        }
        
        _pclose(pipe);
        return result;
    }

public:
    std::string HashString(const std::string& input) {
        return BCryptHashString(input);
    }

    // Get CPU Information with low-level access (HARDWARE)
    std::string GetCPUInfo() {
        int cpuInfo[4] = { 0 };
        std::array<char, 64> brandString = { 0 };

        __cpuid(cpuInfo, 0x80000002);
        memcpy(brandString.data(), cpuInfo, sizeof(cpuInfo));
        
        __cpuid(cpuInfo, 0x80000003);
        memcpy(brandString.data() + 16, cpuInfo, sizeof(cpuInfo));
        
        __cpuid(cpuInfo, 0x80000004);
        memcpy(brandString.data() + 32, cpuInfo, sizeof(cpuInfo));

        __cpuid(cpuInfo, 1);
        DWORD cpuId = cpuInfo[0];

        __cpuid(cpuInfo, 1);
        DWORD signatureEax = cpuInfo[0]; // Contains stepping, model, family
        DWORD featureFlags = cpuInfo[3]; // EDX features
        
        // Get CPU microcode version (more specific info)
        unsigned int microcode = 0;
        
        // Get CPU thermal and power info (harder to spoof)
        __cpuid(cpuInfo, 0x6);
        DWORD thermalInfo = cpuInfo[0];
        
        // Read CPU extended features
        __cpuid(cpuInfo, 7);
        DWORD extFeatures = cpuInfo[1]; // EBX: Extended Features
        
        std::stringstream ss;
        ss << "CPU: " << brandString.data() << std::endl;
        ss << "CPU ID: " << std::hex << std::uppercase << cpuId << std::endl;
        ss << "Signature: " << std::hex << std::uppercase << signatureEax << std::endl;
        ss << "Features: " << std::hex << std::uppercase << featureFlags << std::endl;
        ss << "Microcode: " << std::hex << std::uppercase << microcode << std::endl;
        ss << "Thermal Info: " << std::hex << std::uppercase << thermalInfo << std::endl;
        ss << "Extended Features: " << std::hex << std::uppercase << extFeatures;
        
        return ss.str();
    }
    
    // Get CPU hardware identifier (stabilized version with deeper hardware access)
    std::string GetCPUHardwareID() {
        int cpuInfo[4] = { 0 };
        std::array<char, 64> brandString = { 0 };

        __cpuid(cpuInfo, 0x80000002);
        memcpy(brandString.data(), cpuInfo, sizeof(cpuInfo));
        
        __cpuid(cpuInfo, 0x80000003);
        memcpy(brandString.data() + 16, cpuInfo, sizeof(cpuInfo));
        
        __cpuid(cpuInfo, 0x80000004);
        memcpy(brandString.data() + 32, cpuInfo, sizeof(cpuInfo));

        // Get detailed processor information - family, model, stepping
        __cpuid(cpuInfo, 1);
        int family = ((cpuInfo[0] >> 8) & 0xF) + ((cpuInfo[0] >> 20) & 0xFF);  // Base + Extended Family
        int model = ((cpuInfo[0] >> 4) & 0xF) | ((cpuInfo[0] >> 12) & 0xF0);   // Base + Extended Model
        int stepping = cpuInfo[0] & 0xF;
        DWORD signature = cpuInfo[0];
        
        // Additional CPU features that are hardware-specific and difficult to spoof
        DWORD features = cpuInfo[3];  // Standard features
        
        // Extended processor info
        __cpuid(cpuInfo, 7);
        DWORD extFeatures = cpuInfo[1];  // EBX register contains newer features
        
        // Format as a stable hardware ID string with extended info
        std::stringstream cpuIdStream;
        cpuIdStream << std::string(brandString.data()) << "-" 
                    << std::hex << std::uppercase 
                    << family << model << stepping << "-"
                    << signature << "-"
                    << features << "-"
                    << extFeatures;
        
        return cpuIdStream.str();
    }

    // Motherboard Information (HARDWARE)
    std::string GetMotherboardInfo() {
        HRESULT hres;
        std::string result = "Motherboard Info (HARDWARE):\n";

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return "Failed to initialize COM library";

        IWbemLocator* pLoc = nullptr;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return "Failed to create IWbemLocator object";
        }

        IWbemServices* pSvc = nullptr;
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return "Could not connect to WMI server";
        }

        hres = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "Could not set proxy blanket";
        }

        IEnumWbemClassObject* pEnumerator = nullptr;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_BaseBoard"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "Query for motherboard failed";
        }

        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn == 0) break;

            std::string manufacturer = GetWMIProperty(pclsObj, L"Manufacturer");
            std::string product = GetWMIProperty(pclsObj, L"Product");
            std::string serialNumber = GetWMIProperty(pclsObj, L"SerialNumber");

            result += "  Manufacturer: " + manufacturer + "\n";
            result += "  Model: " + product + "\n";
            result += "  Serial Number: " + serialNumber + "\n";

            pclsObj->Release();
        }

        // Get BIOS information
        pEnumerator->Release();
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_BIOS"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (SUCCEEDED(hres)) {
            while (pEnumerator) {
                hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (uReturn == 0) break;

                std::string biosVersion = GetWMIProperty(pclsObj, L"Version");
                std::string biosSerialNumber = GetWMIProperty(pclsObj, L"SerialNumber");
                std::string manufacturerBIOS = GetWMIProperty(pclsObj, L"Manufacturer");

                result += "BIOS Info (HARDWARE):\n";
                result += "  Manufacturer: " + manufacturerBIOS + "\n";
                result += "  Version: " + biosVersion + "\n";
                result += "  Serial Number: " + biosSerialNumber + "\n";

                pclsObj->Release();
            }
        }

        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        return result;
    }
    
    // Get motherboard hardware ID using direct SMBIOS access
    std::string GetMotherboardHardwareID() {
        HRESULT hres;
        std::string motherboardId = "";
        
        // First try using direct SMBIOS access (harder to spoof than WMI)
        DWORD smbiosSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
        if (smbiosSize > 0) {
            std::vector<BYTE> smbiosData(smbiosSize);
            DWORD bytesRead = GetSystemFirmwareTable('RSMB', 0, smbiosData.data(), smbiosSize);
            
            if (bytesRead > 0) {
                // Process structures to find System Information (Type 1)
                BYTE* ptr = smbiosData.data() + 8; // Skip header
                BYTE* endPtr = smbiosData.data() + smbiosSize;
                std::string manufacturer, product, serialNumber;
                
                while (ptr < endPtr) {
                    BYTE type = *ptr;
                    BYTE length = *(ptr + 1);
                    
                    if (type == 0 && length < 4) break; // End of table
                    
                    if (type == SMBIOS_SYSTEM_INFORMATION && length >= 8) {
                        // Extract string pointers
                        BYTE manufacturerPtr = *(ptr + 4);
                        BYTE productPtr = *(ptr + 5);
                        BYTE serialPtr = *(ptr + 7);
                        
                        // Find the string table
                        BYTE* strPtr = ptr + length;
                        
                        // Extract strings
                        std::vector<std::string> strings;
                        std::string currentStr;
                        
                        while (strPtr < endPtr) {
                            if (*strPtr == 0) {
                                strings.push_back(currentStr);
                                currentStr.clear();
                                
                                // Check for end of string list (double null)
                                if (*(strPtr + 1) == 0) break;
                            }
                            else {
                                currentStr += *strPtr;
                            }
                            strPtr++;
                        }
                        
                        // Assign values from string index
                        if (manufacturerPtr > 0 && manufacturerPtr <= strings.size())
                            manufacturer = strings[manufacturerPtr - 1];
                            
                        if (productPtr > 0 && productPtr <= strings.size())
                            product = strings[productPtr - 1];
                            
                        if (serialPtr > 0 && serialPtr <= strings.size())
                            serialNumber = strings[serialPtr - 1];
                            
                        // Combine to form a unique ID
                        motherboardId = manufacturer + "-" + product + "-" + serialNumber;
                        break;
                    }
                    
                    // Find the next structure
                    BYTE* strPtr = ptr + length;
                    while (strPtr < endPtr && !(*strPtr == 0 && *(strPtr + 1) == 0)) {
                        strPtr++;
                    }
                    ptr = strPtr + 2;
                }
            }
        }
        
        // Fall back to WMI if SMBIOS access didn't yield results
        if (motherboardId.empty()) {
            hres = CoInitializeEx(0, COINIT_MULTITHREADED);
            if (FAILED(hres)) return "";
            
            IWbemLocator* pLoc = nullptr;
            hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
            if (FAILED(hres)) {
                CoUninitialize();
                return "";
            }
            
            IWbemServices* pSvc = nullptr;
            hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
            if (FAILED(hres)) {
                pLoc->Release();
                CoUninitialize();
                return "";
            }
            
            hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                
            if (FAILED(hres)) {
                pSvc->Release();
                pLoc->Release();
                CoUninitialize();
                return "";
            }
            
            // Query motherboard data
            IEnumWbemClassObject* pEnumerator = nullptr;
            hres = pSvc->ExecQuery(
                bstr_t("WQL"),
                bstr_t("SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL,
                &pEnumerator
            );
            
            if (SUCCEEDED(hres)) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;
                
                if (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK && uReturn > 0) {
                    std::string manufacturer = GetWMIProperty(pclsObj, L"Manufacturer");
                    std::string product = GetWMIProperty(pclsObj, L"Product");
                    std::string serialNumber = GetWMIProperty(pclsObj, L"SerialNumber");
                    
                    // Combine to form a unique ID
                    motherboardId = manufacturer + "-" + product + "-" + serialNumber;
                    pclsObj->Release();
                }
                
                pEnumerator->Release();
            }
            
            // Cleanup
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
        }
        
        return motherboardId;
    }

    // Hard Disk Information (HARDWARE)
    std::string GetDiskInfo() {
        std::string result = "Disk Information (HARDWARE):\n";
        
        HRESULT hres;

        // Initialize COM
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return "Failed to initialize COM library";

        // Initialize WMI
        IWbemLocator* pLoc = nullptr;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
            CoUninitialize();
            return "Failed to create IWbemLocator object";
        }

        // Connect to WMI
        IWbemServices* pSvc = nullptr;
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return "Could not connect to WMI server";
        }

        // Set security levels
        hres = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "Could not set proxy blanket";
        }

        // Query disk drive data
        IEnumWbemClassObject* pEnumerator = nullptr;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_DiskDrive"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "Query for disk drives failed";
        }

        // Get the data
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;
        int diskIndex = 0;

        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn == 0) break;

            // Get properties
            std::string model = GetWMIProperty(pclsObj, L"Model");
            std::string serialNumber = GetWMIProperty(pclsObj, L"SerialNumber");
            std::string diskInterface = GetWMIProperty(pclsObj, L"InterfaceType");
            std::string sizeStr = GetWMIProperty(pclsObj, L"Size");

            result += "  Disk " + std::to_string(diskIndex++) + ":\n";
            result += "    Model: " + model + "\n";
            result += "    Serial: " + serialNumber + "\n";
            result += "    Interface: " + diskInterface + "\n";
            
            if (!sizeStr.empty()) {
                uint64_t sizeBytes = std::stoull(sizeStr);
                uint64_t sizeGB = sizeBytes / (1024 * 1024 * 1024);
                result += "    Size: " + std::to_string(sizeGB) + " GB\n";
            }

            pclsObj->Release();
        }

        // Cleanup
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        return result;
    }
    
    // Get disk hardware ID using direct device I/O control
    std::string GetDiskHardwareID() {
        std::stringstream diskIdStream;
        
        // Try direct I/O control first - much harder to spoof
        for (char driveLetter = 'C'; driveLetter <= 'Z'; driveLetter++) {
            std::string physicalDrivePath = "\\\\.\\PhysicalDrive0"; // Start with primary drive
            
            // Open the physical drive
            HANDLE hDrive = CreateFileA(
                physicalDrivePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );
            
            if (hDrive != INVALID_HANDLE_VALUE) {
                // Get device properties using IOCTL
                STORAGE_PROPERTY_QUERY query;
                DWORD bytesReturned = 0;
                char buffer[1024] = { 0 };
                
                query.PropertyId = StorageDeviceProperty;
                query.QueryType = PropertyStandardQuery;
                
                if (DeviceIoControl(
                    hDrive,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    &query,
                    sizeof(query),
                    buffer,
                    sizeof(buffer),
                    &bytesReturned,
                    NULL)) {
                    
                    STORAGE_DEVICE_DESCRIPTOR* deviceDesc = (STORAGE_DEVICE_DESCRIPTOR*)buffer;
                    
                    // Extract model, serial number, and firmware from the descriptor
                    std::string vendor, product, serial;
                    
                    if (deviceDesc->VendorIdOffset > 0 && buffer[deviceDesc->VendorIdOffset] != '\0') {
                        vendor = &buffer[deviceDesc->VendorIdOffset];
                    }
                    
                    if (deviceDesc->ProductIdOffset > 0 && buffer[deviceDesc->ProductIdOffset] != '\0') {
                        product = &buffer[deviceDesc->ProductIdOffset];
                    }
                    
                    if (deviceDesc->SerialNumberOffset > 0 && buffer[deviceDesc->SerialNumberOffset] != '\0') {
                        serial = &buffer[deviceDesc->SerialNumberOffset];
                    }
                    
                    if (!product.empty() && !serial.empty()) {
                        diskIdStream << product << "-" << serial << ";";
                    }
                }
                
                // Try SCSI INQUIRY for additional details
                SCSI_PASS_THROUGH_DIRECT sptd;
                char inquiryBuffer[256] = { 0 };
                
                ZeroMemory(&sptd, sizeof(SCSI_PASS_THROUGH_DIRECT));
                sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
                sptd.CdbLength = 6;
                sptd.DataIn = SCSI_IOCTL_DATA_IN;
                sptd.DataTransferLength = sizeof(inquiryBuffer);
                sptd.DataBuffer = inquiryBuffer;
                sptd.TimeOutValue = 2;
                
                // INQUIRY command
                sptd.Cdb[0] = 0x12; // INQUIRY
                sptd.Cdb[4] = sizeof(inquiryBuffer);
                
                if (DeviceIoControl(
                    hDrive,
                    IOCTL_SCSI_PASS_THROUGH_DIRECT,
                    &sptd,
                    sizeof(SCSI_PASS_THROUGH_DIRECT),
                    &sptd,
                    sizeof(SCSI_PASS_THROUGH_DIRECT),
                    &bytesReturned,
                    NULL)) {
                    
                    // Extract vendor and product data from inquiry response
                    char vendor[9] = { 0 };
                    char product[17] = { 0 };
                    
                    memcpy(vendor, inquiryBuffer + 8, 8);
                    memcpy(product, inquiryBuffer + 16, 16);
                    
                    // Trim spaces
                    std::string vendorStr(vendor);
                    std::string productStr(product);
                    
                    if (!vendorStr.empty() && !productStr.empty()) {
                        diskIdStream << vendorStr << "-" << productStr << ";";
                    }
                }
                
                CloseHandle(hDrive);
            }
            
            break; // For now only check primary drive
        }
        
        // Fallback to WMI if direct access yields no results
        if (diskIdStream.str().empty()) {
            HRESULT hres;
            
            hres = CoInitializeEx(0, COINIT_MULTITHREADED);
            if (FAILED(hres)) return "";
            
            IWbemLocator* pLoc = nullptr;
            hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
            if (FAILED(hres)) {
                CoUninitialize();
                return "";
            }
            
            IWbemServices* pSvc = nullptr;
            hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
            if (FAILED(hres)) {
                pLoc->Release();
                CoUninitialize();
                return "";
            }
            
            hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                
            if (FAILED(hres)) {
                pSvc->Release();
                pLoc->Release();
                CoUninitialize();
                return "";
            }
            
            IEnumWbemClassObject* pEnumerator = nullptr;
            hres = pSvc->ExecQuery(
                bstr_t("WQL"),
                bstr_t("SELECT Model, SerialNumber FROM Win32_DiskDrive"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL,
                &pEnumerator
            );
            
            if (SUCCEEDED(hres)) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;
                
                while (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK && uReturn > 0) {
                    std::string model = GetWMIProperty(pclsObj, L"Model");
                    std::string serialNumber = GetWMIProperty(pclsObj, L"SerialNumber");
                    
                    if (!serialNumber.empty()) {
                        diskIdStream << model << "-" << serialNumber << ";";
                    }
                    
                    pclsObj->Release();
                }
                
                pEnumerator->Release();
            }
            
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
        }
        
        return diskIdStream.str();
    }

    // MAC Address Information (HARDWARE)
    std::string GetMACAddresses() {
        std::string result = "Network Adapters (HARDWARE):\n";
        
        PIP_ADAPTER_INFO pAdapterInfo;
        PIP_ADAPTER_INFO pAdapter = NULL;
        DWORD dwRetVal = 0;

        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
        if (pAdapterInfo == NULL) return "Error allocating memory for adapter info";

        // Make an initial call to GetAdaptersInfo to get the necessary size
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
            if (pAdapterInfo == NULL) return "Error allocating memory for adapter info";
        }

        if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
            pAdapter = pAdapterInfo;
            int i = 0;
            while (pAdapter) {
                result += "  Adapter " + std::to_string(i++) + ":\n";
                result += "    Description: " + std::string(pAdapter->Description) + "\n";
                
                // Format MAC address
                std::stringstream macStream;
                for (UINT j = 0; j < pAdapter->AddressLength; j++) {
                    if (j > 0) macStream << "-";
                    macStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pAdapter->Address[j]);
                }
                result += "    MAC Address: " + macStream.str() + "\n";
                
                pAdapter = pAdapter->Next;
            }
        }
        else {
            result += "  GetAdaptersInfo failed with error: " + std::to_string(dwRetVal) + "\n";
        }

        if (pAdapterInfo) free(pAdapterInfo);

        return result;
    }
    
    // Get MAC address hardware ID
    std::string GetMACHardwareID() {
        std::stringstream macIdStream;
        
        PIP_ADAPTER_INFO pAdapterInfo;
        PIP_ADAPTER_INFO pAdapter = NULL;
        
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
        if (pAdapterInfo == NULL) return "";
        
        // Make an initial call to GetAdaptersInfo to get the necessary size
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
            if (pAdapterInfo == NULL) return "";
        }
        
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            pAdapter = pAdapterInfo;
            
            // Get only physical adapters (Ethernet and WiFi)
            while (pAdapter) {
                // Skip virtual adapters, VPNs, etc.
                if (pAdapter->Type == MIB_IF_TYPE_ETHERNET || pAdapter->Type == IF_TYPE_IEEE80211) {
                    std::stringstream macStream;
                    for (UINT j = 0; j < pAdapter->AddressLength; j++) {
                        if (j > 0) macStream << "-";
                        macStream << std::hex << std::setw(2) << std::setfill('0') 
                                  << static_cast<int>(pAdapter->Address[j]);
                    }
                    macIdStream << macStream.str() << ";";
                }
                pAdapter = pAdapter->Next;
            }
        }
        
        if (pAdapterInfo) free(pAdapterInfo);
        
        return macIdStream.str();
    }

    // GPU Information (HARDWARE)
    std::string GetGPUInfo() {
        std::string result = "GPU Information (HARDWARE):\n";
        
        // Create DXGI Factory
        IDXGIFactory1* pFactory = nullptr;
        HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&pFactory));
        
        if (FAILED(hr)) {
            return result + "  Failed to create DXGI Factory\n";
        }
        
        UINT i = 0;
        IDXGIAdapter1* pAdapter = nullptr;
        
        while (pFactory->EnumAdapters1(i, &pAdapter) != DXGI_ERROR_NOT_FOUND) {
            DXGI_ADAPTER_DESC1 desc;
            pAdapter->GetDesc1(&desc);
            
            char szDescription[256];
            wcstombs_s(nullptr, szDescription, sizeof(szDescription), desc.Description, sizeof(szDescription));
            
            result += "  GPU " + std::to_string(i) + ":\n";
            result += "    Description: " + std::string(szDescription) + "\n";
            result += "    Vendor ID: 0x" + std::to_string(desc.VendorId) + "\n";
            result += "    Device ID: 0x" + std::to_string(desc.DeviceId) + "\n";
            result += "    Dedicated Video Memory: " + 
                      std::to_string(desc.DedicatedVideoMemory / (1024 * 1024)) + " MB\n";
            
            // Device LUID can be used as a unique identifier
            std::stringstream ss;
            ss << std::hex << std::uppercase << desc.AdapterLuid.HighPart 
               << "-" << desc.AdapterLuid.LowPart;
            result += "    Adapter LUID: " + ss.str() + "\n";
            
            SafeRelease(&pAdapter);
            i++;
        }
        
        SafeRelease(&pFactory);
        
        return result;
    }
    
    // Get GPU hardware ID (doesn't change unless GPU is physically changed)
    std::string GetGPUHardwareID() {
        std::stringstream gpuIdStream;
        
        // Create DXGI Factory
        IDXGIFactory1* pFactory = nullptr;
        HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&pFactory));
        
        if (SUCCEEDED(hr)) {
            UINT i = 0;
            IDXGIAdapter1* pAdapter = nullptr;
            
            while (pFactory->EnumAdapters1(i, &pAdapter) != DXGI_ERROR_NOT_FOUND) {
                DXGI_ADAPTER_DESC1 desc;
                pAdapter->GetDesc1(&desc);
                
                // Combine vendor ID and device ID for a hardware identifier
                gpuIdStream << std::hex << std::uppercase 
                           << desc.VendorId << "-" 
                           << desc.DeviceId << "-"
                           << desc.SubSysId << ";";
                
                SafeRelease(&pAdapter);
                i++;
            }
            
            SafeRelease(&pFactory);
        }
        
        return gpuIdStream.str();
    }

    // Monitor Information with EDID details (HARDWARE)
    std::string GetMonitorInfo() {
        std::string result = "Monitor Information (HARDWARE):\n";
        
        HDEVINFO deviceInfoSet = SetupDiGetClassDevs(&GUID_DEVCLASS_MONITOR, NULL, NULL, DIGCF_PRESENT);
        
        if (deviceInfoSet == INVALID_HANDLE_VALUE) {
            return result + "  Failed to get monitor device information\n";
        }
        
        SP_DEVINFO_DATA deviceInfoData;
        deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        
        for (DWORD i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
            result += "  Monitor " + std::to_string(i) + ":\n";
            
            char deviceInstanceID[MAX_PATH];
            if (SetupDiGetDeviceInstanceIdA(deviceInfoSet, &deviceInfoData, deviceInstanceID, sizeof(deviceInstanceID), NULL)) {
                result += "    Device ID: " + std::string(deviceInstanceID) + "\n";
            }
            
            HKEY deviceKey = SetupDiOpenDevRegKey(
                deviceInfoSet, &deviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
                
            if (deviceKey != INVALID_HANDLE_VALUE) {
                char friendlyName[256] = { 0 };
                DWORD dataSize = sizeof(friendlyName);
                DWORD dataType = 0;
                
                if (RegQueryValueExA(deviceKey, "FriendlyName", NULL, &dataType, 
                                    reinterpret_cast<LPBYTE>(friendlyName), &dataSize) == ERROR_SUCCESS) {
                    result += "    Name: " + std::string(friendlyName) + "\n";
                }
                
                RegCloseKey(deviceKey);
            }
            
            // Try to get EDID data (contains manufacturer, model, serial number, etc.)
            HKEY edidKey = SetupDiOpenDevRegKey(
                deviceInfoSet, &deviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
                
            if (edidKey != INVALID_HANDLE_VALUE) {
                BYTE edidData[256] = { 0 };
                DWORD dataSize = sizeof(edidData);
                DWORD dataType = 0;
                
                if (RegQueryValueExA(edidKey, "EDID", NULL, &dataType, edidData, &dataSize) == ERROR_SUCCESS) {
                    // Extract manufacturer ID (3 character code from bytes 8-9)
                    char manufacturerId[4] = { 0 };
                    manufacturerId[0] = 'A' + ((edidData[8] >> 2) & 0x1F) - 1;
                    manufacturerId[1] = 'A' + (((edidData[8] & 0x03) << 3) | ((edidData[9] >> 5) & 0x07)) - 1;
                    manufacturerId[2] = 'A' + (edidData[9] & 0x1F) - 1;
                    
                    result += "    Manufacturer ID: " + std::string(manufacturerId) + "\n";
                    
                    // Extract product ID (bytes 10-11)
                    WORD productId = edidData[10] | (edidData[11] << 8);
                    result += "    Product ID: 0x" + std::to_string(productId) + "\n";
                    
                    // Extract serial number (bytes 12-15)
                    DWORD serialNumber = edidData[12] | (edidData[13] << 8) | 
                                        (edidData[14] << 16) | (edidData[15] << 24);
                    result += "    Serial Number: " + std::to_string(serialNumber) + "\n";
                    
                    // Extract manufacture date (bytes 16-17)
                    BYTE weekOfManufacture = edidData[16];
                    BYTE yearOfManufacture = edidData[17] + 1990;
                    result += "    Manufacture Date: Week " + std::to_string(weekOfManufacture) + 
                              ", Year " + std::to_string(yearOfManufacture) + "\n";
                    
                    // Extract display size (bytes 21-22) in cm
                    if (edidData[21] != 0 && edidData[22] != 0) {
                        result += "    Physical Size: " + std::to_string(edidData[21]) + 
                                 " cm x " + std::to_string(edidData[22]) + " cm\n";
                    }
                    
                    // Generate unique monitor ID from the above data
                    std::stringstream monitorIdStream;
                    monitorIdStream << manufacturerId << "-" << std::hex << productId << "-" << serialNumber;
                    result += "    Monitor ID: " + monitorIdStream.str() + "\n";
                }
                
                RegCloseKey(edidKey);
            }
        }
        
        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        
        return result;
    }
    
    std::string GetMonitorHardwareID() {
        std::stringstream monitorIdStream;
        
        HDEVINFO deviceInfoSet = SetupDiGetClassDevs(&GUID_DEVCLASS_MONITOR, NULL, NULL, DIGCF_PRESENT);
        
        if (deviceInfoSet != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA deviceInfoData;
            deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
            
            for (DWORD i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
                HKEY edidKey = SetupDiOpenDevRegKey(
                    deviceInfoSet, &deviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
                    
                if (edidKey != INVALID_HANDLE_VALUE) {
                    BYTE edidData[256] = { 0 };
                    DWORD dataSize = sizeof(edidData);
                    DWORD dataType = 0;
                    
                    if (RegQueryValueExA(edidKey, "EDID", NULL, &dataType, edidData, &dataSize) == ERROR_SUCCESS) {
                        // Extract manufacturer ID
                        char manufacturerId[4] = { 0 };
                        manufacturerId[0] = 'A' + ((edidData[8] >> 2) & 0x1F) - 1;
                        manufacturerId[1] = 'A' + (((edidData[8] & 0x03) << 3) | ((edidData[9] >> 5) & 0x07)) - 1;
                        manufacturerId[2] = 'A' + (edidData[9] & 0x1F) - 1;
                        
                        // Extract product ID
                        WORD productId = edidData[10] | (edidData[11] << 8);
                        
                        // Extract serial number
                        DWORD serialNumber = edidData[12] | (edidData[13] << 8) | 
                                            (edidData[14] << 16) | (edidData[15] << 24);
                        
                        // Generate unique monitor ID
                        monitorIdStream << manufacturerId << "-" << std::hex << productId 
                                       << "-" << serialNumber << ";";
                    }
                    
                    RegCloseKey(edidKey);
                }
            }
            
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }
        
        return monitorIdStream.str();
    }

    // Get Volume Serial Number (SOFTWARE - can change with reformatting)
    std::string GetVolumeSerialNumber() {
        std::string result = "Volume Information (SOFTWARE - can change with reformatting):\n";
        
        DWORD serialNumber = 0;
        char volumeName[MAX_PATH + 1] = { 0 };
        char fileSystemName[MAX_PATH + 1] = { 0 };
        
        if (GetVolumeInformationA(
            "C:\\", 
            volumeName, 
            ARRAYSIZE(volumeName), 
            &serialNumber, 
            NULL, 
            NULL, 
            fileSystemName, 
            ARRAYSIZE(fileSystemName))) {
            
            result += "  C: Drive\n";
            result += "    Volume Name: " + std::string(volumeName) + "\n";
            result += "    Serial Number: " + std::to_string(serialNumber) + " (0x" + 
                    std::to_string(static_cast<int>(serialNumber)) + ")\n";
            result += "    File System: " + std::string(fileSystemName) + "\n";
        }
        else {
            result += "  Failed to get volume information. Error: " + std::to_string(GetLastError()) + "\n";
        }
        
        return result;
    }
    
    // Get volume software ID (changes with reformatting)
    std::string GetVolumeSoftwareID() {
        std::stringstream volumeIdStream;
        
        DWORD serialNumber = 0;
        if (GetVolumeInformationA("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {
            volumeIdStream << std::hex << std::uppercase << serialNumber;
        }
        
        return volumeIdStream.str();
    }
    
    // Windows Product ID (SOFTWARE - changes with reinstallation)
    std::string GetWindowsProductID() {
        std::string result = "Windows Product ID (SOFTWARE - changes with reinstallation):\n";
        
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            char productId[64] = { 0 };
            DWORD dataSize = sizeof(productId);
            DWORD dataType = 0;
            
            if (RegQueryValueExA(hKey, "ProductId", NULL, &dataType, 
                                reinterpret_cast<LPBYTE>(productId), &dataSize) == ERROR_SUCCESS) {
                result += "  Product ID: " + std::string(productId) + "\n";
            }
            
            // Get Installation ID
            char installationID[64] = { 0 };
            dataSize = sizeof(installationID);
            
            if (RegQueryValueExA(hKey, "DigitalProductId", NULL, &dataType, 
                                reinterpret_cast<LPBYTE>(installationID), &dataSize) == ERROR_SUCCESS) {
                result += "  Digital Product ID: [Binary data]\n";
            }
            
            RegCloseKey(hKey);
        }
        else {
            result += "  Failed to access registry\n";
        }
        
        return result;
    }
    
    // Get Windows software ID (changes with reinstallation)
    std::string GetWindowsSoftwareID() {
        std::string windowsId = "";
        
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            char productId[64] = { 0 };
            DWORD dataSize = sizeof(productId);
            DWORD dataType = 0;
            
            if (RegQueryValueExA(hKey, "ProductId", NULL, &dataType, 
                                reinterpret_cast<LPBYTE>(productId), &dataSize) == ERROR_SUCCESS) {
                windowsId = std::string(productId);
            }
            
            RegCloseKey(hKey);
        }
        
        return windowsId;
    }
    
    // Computer Name (SOFTWARE - user changeable)
    std::string GetComputerName() {
        std::string result = "Computer Name (SOFTWARE - user changeable):\n";
        
        char computerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD size = sizeof(computerName);
        
        if (::GetComputerNameA(computerName, &size)) {
            result += "  Name: " + std::string(computerName) + "\n";
        }
        else {
            result += "  Failed to get computer name. Error: " + std::to_string(GetLastError()) + "\n";
        }
        
        return result;
    }
    
    // Get computer name for software ID
    std::string GetComputerNameSoftwareID() {
        char computerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD size = sizeof(computerName);
        
        if (::GetComputerNameA(computerName, &size)) {
            return std::string(computerName);
        }
        
        return "";
    }
    
    // User Account SID (SOFTWARE - changes with user account)
    std::string GetUserSID() {
        std::string result = "User Account SID (SOFTWARE - changes with user account):\n";
        
        char username[256] = { 0 };
        DWORD usernameSize = sizeof(username);
        
        if (GetUserNameA(username, &usernameSize)) {
            result += "  Username: " + std::string(username) + "\n";
            
            PSID sidPtr = NULL;
            SID_NAME_USE sidType;
            char domainName[256] = { 0 };
            DWORD domainSize = sizeof(domainName);
            DWORD sidSize = 0;
            
            // First call to get size
            LookupAccountNameA(NULL, username, NULL, &sidSize, domainName, &domainSize, &sidType);
            
            if (sidSize > 0) {
                sidPtr = (PSID)malloc(sidSize);
                
                if (LookupAccountNameA(NULL, username, sidPtr, &sidSize, domainName, &domainSize, &sidType)) {
                    LPSTR sidString = NULL;
                    
                    if (::ConvertSidToStringSidA(sidPtr, &sidString)) {
                        result += "  SID: " + std::string(sidString) + "\n";
                        LocalFree(sidString);
                    }
                }
                
                free(sidPtr);
            }
        }
        else {
            result += "  Failed to get username. Error: " + std::to_string(GetLastError()) + "\n";
        }
        
        return result;
    }
    
    // Get user SID for software ID
    std::string GetUserSIDSoftwareID() {
        std::string sidString = "";
        
        char username[256] = { 0 };
        DWORD usernameSize = sizeof(username);
        
        if (GetUserNameA(username, &usernameSize)) {
            PSID sidPtr = NULL;
            SID_NAME_USE sidType;
            char domainName[256] = { 0 };
            DWORD domainSize = sizeof(domainName);
            DWORD sidSize = 0;
            
            // First call to get size
            LookupAccountNameA(NULL, username, NULL, &sidSize, domainName, &domainSize, &sidType);
            
            if (sidSize > 0) {
                sidPtr = (PSID)malloc(sidSize);
                
                if (LookupAccountNameA(NULL, username, sidPtr, &sidSize, domainName, &domainSize, &sidType)) {
                    LPSTR sidStr = NULL;
                    
                    if (::ConvertSidToStringSidA(sidPtr, &sidStr)) {
                        sidString = std::string(sidStr);
                        LocalFree(sidStr);
                    }
                }
                
                free(sidPtr);
            }
        }
        
        return sidString;
    }

    // Generate a hardware-based HWID (doesn't change unless hardware is physically changed)
    std::string GenerateHardwareHWID() {
        // Collect hardware identifiers 
        std::string cpuId = GetCPUHardwareID();
        std::string motherboardId = GetMotherboardHardwareID();
        std::string diskId = GetDiskHardwareID();
        std::string macId = GetMACHardwareID();
        std::string gpuId = GetGPUHardwareID();
        std::string monitorId = GetMonitorHardwareID();
        
        // Combine all hardware IDs
        std::string combinedId = cpuId + "|" + motherboardId + "|" + diskId + "|" 
                               + macId + "|" + gpuId + "|" + monitorId;
        
        // Hash the combined ID to create a fingerprint
        return "Hardware ID: " + HashString(combinedId);
    }
    
    // Generate a software-based HWID (changes with system reinstalls/resets)
    std::string GenerateSoftwareHWID() {
        // Collect software identifiers
        std::string volumeId = GetVolumeSoftwareID();
        std::string windowsId = GetWindowsSoftwareID();
        std::string computerName = GetComputerNameSoftwareID();
        std::string userSid = GetUserSIDSoftwareID();
        
        // Combine all software IDs
        std::string combinedId = volumeId + "|" + windowsId + "|" + computerName + "|" + userSid;
        
        // Hash the combined ID to create a fingerprint
        return "Software ID: " + HashString(combinedId);
    }
    
    // Generate a complete HWID based on combined hardware and software identifiers
    std::string GenerateHWID() {
        // Create a string with key hardware and software identifiers
        std::string hardwareId = GenerateHardwareHWID().substr(13); // Remove "Hardware ID: " prefix
        std::string softwareId = GenerateSoftwareHWID().substr(13); // Remove "Software ID: " prefix
        
        // Combine hardware and software IDs
        return "Complete HWID:\n  Hardware Component: " + hardwareId + "\n  Software Component: " + softwareId;
    }

    // WMIC-Based Hardware Identification Methods
    // WARNING: These methods use WMIC which can be easily spoofed and are NOT recommended for secure hardware identification
    
    std::string GetWMICBasedWarning() {
        std::stringstream ss;
        ss << "====================================================" << std::endl;
        ss << "  WARNING: WMIC-BASED IDENTIFIERS (LESS RELIABLE)   " << std::endl;
        ss << "====================================================" << std::endl << std::endl;
        ss << "The following identifiers are retrieved using Windows Management" << std::endl;
        ss << "Instrumentation Command-line (WMIC) and can be easily spoofed or" << std::endl;
        ss << "altered. They should NOT be used for secure hardware identification." << std::endl;
        ss << "For reliable identification, use the hardware-based methods above." << std::endl << std::endl;
        return ss.str();
    }

    std::string GetWMICBasedCPUInfo() {
        std::stringstream ss;
        ss << "WMIC CPU Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("cpu get Name, ProcessorId, Manufacturer, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors /format:list");
        return ss.str();
    }

    std::string GetWMICBasedMotherboardInfo() {
        std::stringstream ss;
        ss << "WMIC Motherboard Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("baseboard get Manufacturer, Product, SerialNumber, Version /format:list");
        return ss.str();
    }

    std::string GetWMICBasedBIOSInfo() {
        std::stringstream ss;
        ss << "WMIC BIOS Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("bios get Manufacturer, SMBIOSBIOSVersion, SerialNumber, Version /format:list");
        return ss.str();
    }

    std::string GetWMICBasedDiskInfo() {
        std::stringstream ss;
        ss << "WMIC Disk Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("diskdrive get Model, SerialNumber, Size, MediaType /format:list");
        return ss.str();
    }

    std::string GetWMICBasedNetworkAdapterInfo() {
        std::stringstream ss;
        ss << "WMIC Network Adapter Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("nicconfig get Description, MACAddress, IPAddress /format:list");
        return ss.str();
    }

    std::string GetWMICBasedGPUInfo() {
        std::stringstream ss;
        ss << "WMIC GPU Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("path win32_VideoController get Name, DriverVersion, VideoProcessor, AdapterRAM /format:list");
        return ss.str();
    }

    std::string GetWMICBasedOSInfo() {
        std::stringstream ss;
        ss << "WMIC OS Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("os get Caption, SerialNumber, Version, OSArchitecture /format:list");
        return ss.str();
    }

    std::string GetWMICBasedMemoryInfo() {
        std::stringstream ss;
        ss << "WMIC Memory Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("memorychip get BankLabel, Capacity, PartNumber, Speed /format:list");
        return ss.str();
    }

    std::string GetWMICBasedLogicalDiskInfo() {
        std::stringstream ss;
        ss << "WMIC Logical Disk Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("logicaldisk get DeviceID, FileSystem, Size, VolumeSerialNumber /format:list");
        return ss.str();
    }

    std::string GetWMICBasedSMBIOSInfo() {
        std::stringstream ss;
        ss << "WMIC SMBIOS Information (Unreliable):" << std::endl;
        ss << ExecuteWMICCommand("path win32_SystemEnclosure get SerialNumber, SMBIOSAssetTag, Manufacturer /format:list");
        return ss.str();
    }

    std::string GetAllWMICBasedInfo() {
        std::stringstream ss;
        // Warning is added here only once
        ss << GetWMICBasedWarning();
        ss << GetWMICBasedCPUInfo() << std::endl;
        ss << GetWMICBasedMotherboardInfo() << std::endl;
        ss << GetWMICBasedBIOSInfo() << std::endl;
        ss << GetWMICBasedDiskInfo() << std::endl;
        ss << GetWMICBasedNetworkAdapterInfo() << std::endl;
        ss << GetWMICBasedGPUInfo() << std::endl;
        ss << GetWMICBasedOSInfo() << std::endl;
        ss << GetWMICBasedMemoryInfo() << std::endl;
        ss << GetWMICBasedLogicalDiskInfo() << std::endl;
        ss << GetWMICBasedSMBIOSInfo() << std::endl;
        
        ss << std::endl << "Note: The above information can be easily modified or spoofed." << std::endl;
        ss << "For reliable hardware identification, use the hardware-based methods." << std::endl;
        
        return ss.str();
    }

    std::string GetInstallDate() {
        std::string result = "Windows Install Date (SOFTWARE):\n";
        
        HKEY hKey;
        LONG lRes = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
            KEY_READ,
            &hKey);
            
        if (lRes == ERROR_SUCCESS) {
            DWORD installDateDword = 0;
            DWORD dataSize = sizeof(installDateDword);
            DWORD dataType = 0;
            
            lRes = RegQueryValueExA(
                hKey,
                "InstallDate",
                0,
                &dataType,
                reinterpret_cast<LPBYTE>(&installDateDword),
                &dataSize);
                
            if (lRes == ERROR_SUCCESS && dataType == REG_DWORD) {
                time_t installTime = static_cast<time_t>(installDateDword);
                
                char dateStr[100];
                struct tm* timeinfo = localtime(&installTime);
                strftime(dateStr, sizeof(dateStr), "%Y-%m-%d %H:%M:%S", timeinfo);
                
                result += "  Install Date: " + std::string(dateStr) + "\n";
                result += "  Unix Timestamp: " + std::to_string(installDateDword) + "\n";
            }
            else {
                result += "  Failed to get install date. Error: " + std::to_string(lRes) + "\n";
            }
            
            RegCloseKey(hKey);
        }
        else {
            result += "  Failed to open registry key. Error: " + std::to_string(lRes) + "\n";
        }
        
        return result;
    }
    
    std::string GetUserInfo() {
        std::string result = "User Information (SOFTWARE):\n";
        
        char username[UNLEN + 1];
        DWORD usernameLen = UNLEN + 1;
        
        if (GetUserNameA(username, &usernameLen)) {
            result += "  Username: " + std::string(username) + "\n";
        }
        else {
            result += "  Failed to get username. Error: " + std::to_string(GetLastError()) + "\n";
        }
        
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD computerNameLen = MAX_COMPUTERNAME_LENGTH + 1;
        
        if (::GetComputerNameA(computerName, &computerNameLen)) {
            result += "  Computer Name: " + std::string(computerName) + "\n";
        }
        else {
            result += "  Failed to get computer name. Error: " + std::to_string(GetLastError()) + "\n";
        }
        
        return result;
    }
    
    std::string GetOSInfo() {
        std::string result = "Operating System Information (SOFTWARE):\n";
        
        // Use RtlGetVersion which is more reliable than GetVersionEx
        typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
        if (hMod) {
            RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
            if (RtlGetVersion) {
                RTL_OSVERSIONINFOW osvi = { 0 };
                osvi.dwOSVersionInfoSize = sizeof(osvi);
                if (NT_SUCCESS(RtlGetVersion(&osvi))) {
                    result += "  Windows Version: " + std::to_string(osvi.dwMajorVersion) + "." +
                              std::to_string(osvi.dwMinorVersion) + "." + 
                              std::to_string(osvi.dwBuildNumber) + "\n";
                    
                    if (osvi.szCSDVersion[0] != L'\0') {
                        // Convert wide string to narrow string
                        char csdVersion[128] = { 0 };
                        WideCharToMultiByte(CP_ACP, 0, osvi.szCSDVersion, -1, 
                                          csdVersion, sizeof(csdVersion), NULL, NULL);
                        result += "  Service Pack: " + std::string(csdVersion) + "\n";
                    }
                }
            }
        }
        
        // Get more detailed information from registry
        HKEY hKey;
        LONG lRes = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
            KEY_READ,
            &hKey);
            
        if (lRes == ERROR_SUCCESS) {
            char productName[256] = { 0 };
            DWORD dataSize = sizeof(productName);
            DWORD dataType = 0;
            
            if (RegQueryValueExA(hKey, "ProductName", 0, &dataType, 
                               reinterpret_cast<LPBYTE>(productName), &dataSize) == ERROR_SUCCESS) {
                result += "  Product Name: " + std::string(productName) + "\n";
            }
            
            char editionID[256] = { 0 };
            dataSize = sizeof(editionID);
            
            if (RegQueryValueExA(hKey, "EditionID", 0, &dataType, 
                               reinterpret_cast<LPBYTE>(editionID), &dataSize) == ERROR_SUCCESS) {
                result += "  Edition ID: " + std::string(editionID) + "\n";
            }
            
            char releaseId[256] = { 0 };
            dataSize = sizeof(releaseId);
            
            if (RegQueryValueExA(hKey, "ReleaseId", 0, &dataType, 
                               reinterpret_cast<LPBYTE>(releaseId), &dataSize) == ERROR_SUCCESS) {
                result += "  Release ID: " + std::string(releaseId) + "\n";
            }
            
            char currentBuild[256] = { 0 };
            dataSize = sizeof(currentBuild);
            
            if (RegQueryValueExA(hKey, "CurrentBuild", 0, &dataType, 
                               reinterpret_cast<LPBYTE>(currentBuild), &dataSize) == ERROR_SUCCESS) {
                result += "  Current Build: " + std::string(currentBuild) + "\n";
            }
            
            char ubr[256] = { 0 };
            dataSize = sizeof(ubr);
            DWORD ubrDword = 0;
            
            if (RegQueryValueExA(hKey, "UBR", 0, &dataType, 
                               reinterpret_cast<LPBYTE>(&ubrDword), &dataSize) == ERROR_SUCCESS) {
                result += "  UBR: " + std::to_string(ubrDword) + "\n";
                
                // Combine build number and UBR
                if (currentBuild[0] != '\0') {
                    result += "  Full Build: " + std::string(currentBuild) + "." + 
                             std::to_string(ubrDword) + "\n";
                }
            }
            
            RegCloseKey(hKey);
        }
        
        // Get system architecture
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        
        std::string architecture;
        switch (sysInfo.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                architecture = "x64 (AMD64)";
                break;
            case PROCESSOR_ARCHITECTURE_INTEL:
                architecture = "x86 (Intel)";
                break;
            case PROCESSOR_ARCHITECTURE_ARM:
                architecture = "ARM";
                break;
            case PROCESSOR_ARCHITECTURE_ARM64:
                architecture = "ARM64";
                break;
            default:
                architecture = "Unknown";
        }
        
        result += "  System Architecture: " + architecture + "\n";
        
        return result;
    }
};

int main() {
    try {
        HWIDGrabber hwid;
        
        std::cout << "===== github.com/0vm =====" << std::endl << std::endl;
        
        // Hardware-based identifiers
        std::cout << "=============================" << std::endl;
        std::cout << "  HARDWARE-BASED IDENTIFIERS " << std::endl;
        std::cout << "=============================" << std::endl << std::endl;
        
        std::cout << "Getting CPU info..." << std::endl;
        std::cout << hwid.GetCPUInfo() << std::endl;
        std::string cpuId = hwid.GetCPUHardwareID();
        std::cout << "  Raw CPU ID: " << cpuId << std::endl;
        std::cout << "  Hashed CPU ID: " << hwid.HashString(cpuId) << std::endl << std::endl;
        
        std::cout << "Getting motherboard info..." << std::endl;
        std::cout << hwid.GetMotherboardInfo() << std::endl;
        std::string mbId = hwid.GetMotherboardHardwareID();
        std::cout << "  Raw Motherboard ID: " << mbId << std::endl;
        std::cout << "  Hashed Motherboard ID: " << hwid.HashString(mbId) << std::endl << std::endl;
        
        std::cout << "Getting disk info..." << std::endl;
        std::cout << hwid.GetDiskInfo() << std::endl;
        std::string diskId = hwid.GetDiskHardwareID();
        std::cout << "  Raw Disk ID: " << diskId << std::endl;
        std::cout << "  Hashed Disk ID: " << hwid.HashString(diskId) << std::endl << std::endl;
        
        std::cout << "Getting MAC addresses..." << std::endl;
        std::cout << hwid.GetMACAddresses() << std::endl;
        std::string macId = hwid.GetMACHardwareID();
        std::cout << "  Raw MAC ID: " << macId << std::endl;
        std::cout << "  Hashed MAC ID: " << hwid.HashString(macId) << std::endl << std::endl;
        
        std::cout << "Getting GPU info..." << std::endl;
        std::cout << hwid.GetGPUInfo() << std::endl;
        std::string gpuId = hwid.GetGPUHardwareID();
        std::cout << "  Raw GPU ID: " << gpuId << std::endl;
        std::cout << "  Hashed GPU ID: " << hwid.HashString(gpuId) << std::endl << std::endl;
        
        std::cout << "Getting monitor info..." << std::endl;
        std::cout << hwid.GetMonitorInfo() << std::endl;
        std::string monitorId = hwid.GetMonitorHardwareID();
        std::cout << "  Raw Monitor ID: " << monitorId << std::endl;
        std::cout << "  Hashed Monitor ID: " << hwid.HashString(monitorId) << std::endl << std::endl;
        
        // Software-based identifiers
        std::cout << "=============================" << std::endl;
        std::cout << "  SOFTWARE-BASED IDENTIFIERS " << std::endl;
        std::cout << "=============================" << std::endl << std::endl;
        
        std::cout << "Getting volume serial number..." << std::endl;
        std::cout << hwid.GetVolumeSerialNumber() << std::endl;
        std::string volumeId = hwid.GetVolumeSoftwareID();
        std::cout << "  Raw Volume ID: " << volumeId << std::endl;
        std::cout << "  Hashed Volume ID: " << hwid.HashString(volumeId) << std::endl << std::endl;
        
        std::cout << "Getting Windows product ID..." << std::endl;
        std::cout << hwid.GetWindowsProductID() << std::endl;
        std::string windowsId = hwid.GetWindowsSoftwareID();
        std::cout << "  Raw Windows ID: " << windowsId << std::endl;
        std::cout << "  Hashed Windows ID: " << hwid.HashString(windowsId) << std::endl << std::endl;
        
        std::cout << "Getting computer name..." << std::endl;
        std::cout << hwid.GetComputerName() << std::endl;
        std::string computerNameId = hwid.GetComputerNameSoftwareID();
        std::cout << "  Raw Computer Name ID: " << computerNameId << std::endl;
        std::cout << "  Hashed Computer Name ID: " << hwid.HashString(computerNameId) << std::endl << std::endl;
        
        std::cout << "Getting user SID..." << std::endl;
        std::cout << hwid.GetUserSID() << std::endl;
        std::string userId = hwid.GetUserSIDSoftwareID();
        std::cout << "  Raw User SID: " << userId << std::endl;
        std::cout << "  Hashed User SID: " << hwid.HashString(userId) << std::endl << std::endl;
        
        // Generate combined HWID
        std::cout << "=============================" << std::endl;
        std::cout << "      COMBINED HWIDs        " << std::endl;
        std::cout << "=============================" << std::endl << std::endl;
        
        // Hardware HWID - combine raw IDs first
        std::string combinedHardwareId = cpuId + "|" + mbId + "|" + diskId + "|" + macId + "|" + gpuId + "|" + monitorId;
        std::cout << "Raw Combined Hardware ID:" << std::endl;
        std::cout << "  " << combinedHardwareId << std::endl << std::endl;
        
        std::cout << "Hashed Hardware ID:" << std::endl;
        std::cout << "  " << hwid.HashString(combinedHardwareId) << std::endl << std::endl;
        
        // Software HWID - combine raw IDs first
        std::string combinedSoftwareId = volumeId + "|" + windowsId + "|" + computerNameId + "|" + userId;
        std::cout << "Raw Combined Software ID:" << std::endl;
        std::cout << "  " << combinedSoftwareId << std::endl << std::endl;
        
        std::cout << "Hashed Software ID:" << std::endl;
        std::cout << "  " << hwid.HashString(combinedSoftwareId) << std::endl << std::endl;
        
        // Complete HWID
        std::cout << "Complete HWID:" << std::endl;
        std::cout << "  Hardware Component: " << hwid.HashString(combinedHardwareId) << std::endl;
        std::cout << "  Software Component: " << hwid.HashString(combinedSoftwareId) << std::endl << std::endl;
        
        // WMIC-based identifiers - Don't print the warning as GetAllWMICBasedInfo already includes it
        std::cout << hwid.GetAllWMICBasedInfo() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception caught!" << std::endl;
    }
    
    return 0;
} 
