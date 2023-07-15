# Simple HWID Checker

The Simple HWID Checker is a hardware identification or HWID tool that collects system-specific information such as hard drive data, computer name, CPU hash, GPU information, total system memory, MAC address, and BIOS serial number.

## How to Use

1. Compile the C++ code.
2. Run the compiled executable.
3. The console will display various hardware information of the system.

## Code Overview

This application is written in C++ and uses various Windows APIs, as well as DirectX and WMI libraries, to fetch system-specific data.

**Primary functions:**

- `getGraphicsCardInfo()`: Retrieves the graphics card info.
- `getTotalSystemMemory()`: Retrieves the total system memory.
- `getMACaddress()`: Retrieves the MAC address of the system.
- `getBiosSerialNumber()`: Retrieves the BIOS serial number.

The `main()` function makes calls to all these functions and fetches information about the system's volume, computer name, CPU hash, and more.

```c++
int main()
{   
    // Fetches the GPU information
    std::vector<std::string> graphicsCards = getGraphicsCardInfo();
    // ...

    // Fetches the total system memory
    DWORDLONG totalMemoryMB = getTotalSystemMemory();
    // ...

    // Fetches the MAC address
    std::string macAddress = getMACaddress();
    // ...

    // Fetches the BIOS serial number
    std::string biosSerial = getBiosSerialNumber();
    // ...
}
```
## Dependencies

This project relies on the following Windows libraries:

- `Windows.h`
- `Iphlpapi.h`
- `Assert.h`
- `tchar.h`
- `intrin.h`
- `dxgi.h`
- `Psapi.h`
- `comdef.h`
- `Wbemidl.h`

Make sure to link the following libraries in your project settings:

- `dxgi.lib`
- `iphlpapi.lib`
- `wbemuuid.lib`


## Credit

This project is inspired by and has improved upon the original HWID Info Grabber by HeathHowren, available at [this link](https://github.com/HeathHowren/HWID-Info-Grabber/tree/master). The following improvements have been made:

- Addition of network information gathering, making use of the `Iphlpapi.h` library.
- Incorporation of debug assertions via the `Assert.h` library for better debugging.
- Utilisation of the DirectX Graphics Infrastructure (`dxgi.h`) for enhanced graphics-related operations.
- Inclusion of process and system information access via `Psapi.h`.

## License

This project is licensed under MIT License.
