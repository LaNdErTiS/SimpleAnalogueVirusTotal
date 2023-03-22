import ctypes
from ctypes import wintypes

psapi = ctypes.WinDLL('psapi.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')


# region Structures
class MODULEINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', wintypes.LPVOID),
                ('SizeOfImage', wintypes.DWORD),
                ('EntryPoint',  wintypes.LPVOID)]


class DOSHeader(ctypes.Structure):
    _fields_ = [
        ('e_magic',     wintypes.WORD),
        ('e_cblp',      wintypes.WORD),
        ('e_cp',        wintypes.WORD),
        ('e_crlc',      wintypes.WORD),
        ('e_cparhdr',   wintypes.WORD),
        ('e_minalloc',  wintypes.WORD),
        ('e_maxalloc',  wintypes.WORD),
        ('e_ss',        wintypes.WORD),
        ('e_sp',        wintypes.WORD),
        ('e_csum',      wintypes.WORD),
        ('e_ip',        wintypes.WORD),
        ('e_cs',        wintypes.WORD),
        ('e_lfarlc',    wintypes.WORD),
        ('e_ovno',      wintypes.WORD),
        ('e_res1',      wintypes.WORD * 4),
        ('e_oemid',     wintypes.WORD),
        ('e_oeminfo',   wintypes.WORD),
        ('e_res2',      wintypes.WORD * 10),
        ('e_lfanew',    wintypes.WORD)
    ]


class PEHeader(ctypes.Structure):
    _fields_ = [
        # PE HEADER
        ('Signature',               wintypes.DWORD),
        ('Machine',                 wintypes.WORD),
        ('NumberOfSections',        wintypes.WORD),
        ('TimeDateStamp',           wintypes.DWORD),
        ('PointerToSymbolTable',    wintypes.DWORD),
        ('NumberOfSymbols',         wintypes.DWORD),
        ('SizeOfOptionalHeader',    wintypes.WORD),
        ('Characteristics',         wintypes.WORD)
    ]


class SectionHeader(ctypes.Structure):
    _fields_ = [
        ('Name',                    wintypes.BYTE * 8),
        ('VirtualSize',             wintypes.DWORD),
        ('VirtualAddress',          wintypes.DWORD),
        ('SizeOfRawData',           wintypes.DWORD),
        ('PointerToRawData',        wintypes.DWORD),
        ('PonterToRelocations',     wintypes.DWORD),
        ('PointerToLineNumbers',    wintypes.DWORD),
        ('NumberOfRelocations',     wintypes.WORD),
        ('NumberOfLineNumbers',     wintypes.WORD),
        ('Characteristics',         wintypes.DWORD)
    ]


# endregion

# region WinAPI Function Declarations

# region kernel32.dll
#
# DWORD GetLastError();
#
GetLastError = kernel32.GetLastError
GetLastError.restype = wintypes.DWORD

#
# HANDLE OpenProcess(
#  [in] DWORD dwDesiredAccess,
#  [in] BOOL  bInheritHandle,
#  [in] DWORD dwProcessId
# );
#
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

# OpenProcess Desired Access Values
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

#
# BOOL ReadProcessMemory(
#  [in]  HANDLE  hProcess,
#  [in]  LPCVOID lpBaseAddress,
#  [out] LPVOID  lpBuffer,
#  [in]  SIZE_T  nSize,
#  [out] SIZE_T  *lpNumberOfBytesRead
# );
#
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

# endregion

# region psapi.dll
# DWORD GetProcessImageFileNameA(
#   [in]  HANDLE hProcess,
#   [out] LPSTR  lpImageFileName,
#   [in]  DWORD  nSize
# );
GetProcessImageFileName = psapi.GetProcessImageFileNameA
GetProcessImageFileName.argtypes = [wintypes.HANDLE, wintypes.LPSTR, wintypes.DWORD]
GetProcessImageFileName.restype = wintypes.DWORD

# DWORD GetModuleFileNameExA(
#   [in]           HANDLE  hProcess,
#   [in, optional] HMODULE hModule,
#   [out]          LPSTR   lpFilename,
#   [in]           DWORD   nSize
# );
GetModuleFileName = psapi.GetModuleFileNameExA
GetModuleFileName.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
GetModuleFileName.restype = wintypes.DWORD

# BOOL EnumProcessModules(
#   [in]  HANDLE  hProcess,
#   [out] HMODULE *lphModule,
#   [in]  DWORD   cb,
#   [out] LPDWORD lpcbNeeded
# );
EnumProcessModules = psapi.EnumProcessModules
EnumProcessModules.restype = wintypes.BOOL
EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, wintypes.LPDWORD]

# BOOL GetModuleInformation(
#   [in]  HANDLE       hProcess,
#   [in]  HMODULE      hModule,
#   [out] LPMODULEINFO lpmodinfo,
#   [in]  DWORD        cb
# );
GetModuleInformation = psapi.GetModuleInformation
GetModuleInformation.restype = wintypes.BOOL
GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]

# endregion

# endregion
