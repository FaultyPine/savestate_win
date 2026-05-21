#pragma once


#include <windows.h>
#include <iostream>
#include <string>
void PrintError(DWORD err);

// Function to convert memory state to string
std::string GetMemoryState(DWORD state) {
    if (state == MEM_COMMIT) return "MEM_COMMIT";
    if (state == MEM_RESERVE) return "MEM_RESERVE";
    if (state == MEM_FREE) return "MEM_FREE";
    return "UNKNOWN_STATE";
}

// Function to convert memory type to string
std::string GetMemoryType(DWORD type) {
    if (type == MEM_PRIVATE) return "MEM_PRIVATE";
    if (type == MEM_MAPPED) return "MEM_MAPPED";
    if (type == MEM_IMAGE) return "MEM_IMAGE";
    return "UNKNOWN_TYPE";
}

// Function to convert memory protection to string
std::string GetMemoryProtection(DWORD protect) {
    std::string prot_str;
    if (protect & PAGE_NOACCESS) prot_str += "NOACCESS | ";
    if (protect & PAGE_READONLY) prot_str += "READONLY | ";
    if (protect & PAGE_READWRITE) prot_str += "READWRITE | ";
    if (protect & PAGE_WRITECOPY) prot_str += "WRITECOPY | ";
    if (protect & PAGE_EXECUTE) prot_str += "EXECUTE | ";
    if (protect & PAGE_EXECUTE_READ) prot_str += "EXECUTE_READ | ";
    if (protect & PAGE_EXECUTE_READWRITE) prot_str += "EXECUTE_READWRITE | ";
    if (protect & PAGE_EXECUTE_WRITECOPY) prot_str += "EXECUTE_WRITECOPY | ";
    if (prot_str.empty()) return "UNKNOWN_PROTECTION";
    return prot_str.substr(0, prot_str.length() - 3); // Remove trailing " | "
}


bool PrintProcessMemoryRegion(HANDLE hProcess, void* lpAddress, MEMORY_BASIC_INFORMATION& mbi)
{
    if (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi))) {
        std::cout << "Base Address: 0x" << std::hex << mbi.BaseAddress
            << ", Size: 0x" << mbi.RegionSize
            << ", State: " << GetMemoryState(mbi.State)
            << ", Protect: " << GetMemoryProtection(mbi.Protect)
            << ", Type: " << GetMemoryType(mbi.Type) << std::endl;
        if ((mbi.State & MEM_COMMIT) != 0 &&
            (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE) && mbi.Type != MEM_IMAGE && mbi.BaseAddress != nullptr)
        {
            size_t bytesToRead = mbi.RegionSize;
            char* buffer = new char[mbi.RegionSize];
            size_t numBytesRead = 0;
            if (ReadProcessMemory(hProcess, lpAddress, (void*)buffer, mbi.RegionSize, &numBytesRead) && mbi.RegionSize > 0)
            {
                std::cout << "First few bytes: ";
                for (int i = 0; i < 0x64 && i < mbi.RegionSize; ++i) {
                    if (buffer[i] == 0)
                    {
                        std::cout << "0";
                        continue;
                    }
                    std::cout << ((char*)buffer)[i];
                }
                std::cout << "\n";
            }
            else
            {
                DWORD err = GetLastError();
                std::cerr << "Failed to read memory at address: 0x" << std::hex << mbi.BaseAddress << std::endl;
                PrintError(err);
            }
            delete[] buffer;
            std::cout << "\n";
        }
        return true;
    }

    if (GetLastError() != ERROR_INVALID_PARAMETER) { // ERROR_INVALID_PARAMETER can occur at end of address space
        std::cerr << "Error querying memory region: " << GetLastError() << std::endl;
    }
    return false;
}

void PrintProcessMemoryRegions(HANDLE hProcess) {
    LPVOID lpAddress = 0;
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    while (PrintProcessMemoryRegion(hProcess, lpAddress, mbi)) {
        lpAddress = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    if (GetLastError() != ERROR_INVALID_PARAMETER) { // ERROR_INVALID_PARAMETER can occur at end of address space
        std::cerr << "Error querying memory regions: " << GetLastError() << std::endl;
    }
}
