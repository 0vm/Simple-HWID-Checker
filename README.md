# Simple HWID Checker

The HWID Checker is an easy to use but not so simple hardware identification tool that collects detailed system information using low-level direct hardware access methods. It provides hardware identifiers that are difficult to spoof or modify, making it suitable for secure hardware identification.

## Code Overview

This application is written in C++ and uses direct hardware access methods, as well as Windows APIs, to fetch system-specific data that is difficult to spoof.

**Key Functions:**

- **Hardware Identifiers:**
  - `GetCPUInfo()`: Retrieves detailed CPU information using direct CPUID instruction
  - `GetMotherboardInfo()`: Extracts motherboard data from SMBIOS tables
  - `GetDiskInfo()`: Accesses physical disk properties using DeviceIoControl
  - `GetGPUInfo()`: Enumerates graphics hardware through DirectX interfaces
  - `GetMonitorInfo()`: Retrieves EDID data directly from display devices
  - `GetNetworkInfo()`: Collects network adapter information via low-level API calls
  - `GetMACHardwareID()`: Generates unique identifier based on MAC addresses
  - `GetBIOSInfo()`: Extracts BIOS data through direct memory access
  - `GetTPMInfo()`: Communicates with the Trusted Platform Module for secure identifiers
  - `GetRAMInfo()`: Retrieves memory configuration and hardware details

- **Software Identifiers:**
  - `GetOSInfo()`: Gathers detailed OS version information using RtlGetVersion
  - `GetUserInfo()`: Retrieves current user and computer name
  - `GetVolumeInfo()`: Extracts storage volume details and serial numbers
  - `GetWindowsProductID()`: Accesses Windows licensing information
  - `GetInstallationTime()`: Determines Windows installation timestamp

- **Processing & Generation:**
  - `HashString()`: Creates cryptographic hashes of hardware identifiers
  - `GenerateHardwareHWID()`: Combines hardware identifiers into a unified fingerprint
  - `GenerateSoftwareHWID()`: Creates a software environment fingerprint
  - `GetSystemUUID()`: Retrieves the system's unique universal identifier
  - `GetAllHardwareIDs()`: Collects all hardware identifiers in one call
  - `GetAllSoftwareIDs()`: Retrieves all software environment identifiers
  - `ConvertToHexString()`: Formats binary data into readable hexadecimal
  - `FormatIdentifier()`: Standardises identifier formatting


## Direct Hardware Access Methods

This tool uses **low-level Windows APIs and direct hardware access methods** to retrieve hardware identifiers that are difficult to spoof:

- Native Windows API calls
- Direct device I/O control codes
- Low-level CPUID instruction access
- DirectX interfaces for GPU enumeration
- SetupAPI for detailed device enumeration
- Raw SMBIOS/EDID data parsing
- Direct TPM (Trusted Platform Module) access
- BCrypt cryptographic operations

## Features

- **Hardware Identifiers** (using low-level direct access):
  - CPU information (brand string, ID, signature, features)
  - Motherboard details (manufacturer, model, serial number)
  - Disk drive information (model, serial number, interface)
  - Network adapter MAC addresses
  - GPU details (vendor ID, device ID, memory)
  - Monitor information (EDID data, manufacturer, serial)
  - TPM (Trusted Platform Module) data

- **Software Identifiers**:
  - Volume serial numbers
  - Windows product ID
  - Computer name
  - User account SID
  - Installation date

- **Generated IDs**:
  - Individual component IDs (both raw and hashed)
  - Combined hardware identifier (spoof-resistant)
  - Combined software identifier
  - Complete system HWID

- **WMIC-Based Identifiers** (included for comparison only):
  - Various hardware information retrieved via WMIC
  - Clearly marked as unreliable and not recommended for secure identification

## Warning About WMIC-Based Identifiers

> ⚠️ **WARNING**: WMIC-based identifiers can be easily altered or spoofed and should not be considered trustworthy for secure identification purposes. The tool clearly marks these as unreliable.

While this tool primarily uses secure direct hardware access methods, it also includes WMIC-based identifiers for educational and comparison purposes. These are explicitly marked as unreliable in the program output.

## Dependencies

This project relies on the following libraries:

- Windows API (`Windows.h`)
- IP Helper API (`Iphlpapi.h`)
- Intel Intrinsics (`intrin.h`)
- COM Definitions (`comdef.h`)
- WMI Interface (`Wbemidl.h`)
- Setup API (`SetupAPI.h`)
- Device GUID (`devguid.h`)
- DirectX Graphics Infrastructure (`dxgi.h`, `dxgi1_6.h`, `d3d11.h`)
- Storage Device Interface (`ntddscsi.h`, `winioctl.h`)
- ATL Base (`atlbase.h`)
- Shell API (`shlwapi.h`)
- Cryptography API (`Wincrypt.h`, `bcrypt.h`, `ncrypt.h`)
- Terminal Services (`Wtsapi32.h`)
- Security Descriptor (`sddl.h`)
- Windows NT API (`winternl.h`)

Required libraries to link:
```
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
```

## License

This project is licensed under the [MIT License](LICENSE).

### Tags
HWID Checker, HWID Grabber, Hardware ID Authentication
