import ctypes.wintypes
import logging
import time

from memory.winapihelper import *
from daemons.daemon_base import Context, initMultiprocessingLogger

import pefile

logger: logging.Logger = logging.getLogger()

sections_to_validate = ['.text']


def validate_section(pe_file: pefile.PE, process: wintypes.HANDLE, baseAddr, section: SectionHeader) -> \
        tuple[str, dict] | None:
    section_name = bytearray(section.Name).strip(b'\x00').decode('ascii')
    if section_name not in sections_to_validate:
        return None

    section_addr = baseAddr + section.VirtualAddress
    pe_section = next((x for x in pe_file.sections if x.Name.strip(b'\x00').decode('ascii') == section_name), None)
    if not pe_section:
        logger.warning(f'Cannot find section {section_name}')
        return section_name, {'result': 'suspicious', 'reason': 'exe_section_not_found'}

    c_section_data = (ctypes.c_ubyte * section.VirtualSize)()
    c_outcb = ctypes.c_size_t()
    res = ReadProcessMemory(process, section_addr, c_section_data, ctypes.sizeof(c_section_data),
                            ctypes.byref(c_outcb))
    if res == 0:
        logger.error(f'Cannot read section from process 0x{process:X} - err={GetLastError()}')
        return section_name, {'result': 'unknown', 'reason': 'unable_read_from_memory'}

    suspicious_reasons = []
    pe_section_data = pe_section.get_data()
    section_data = bytearray(c_section_data)
    section_data_size = len(section_data)
    pe_section_data_size = pe_section.Misc_VirtualSize
    if section_data_size != pe_section_data_size:
        suspicious_reasons.append({'reason': f'unequal_section_size',
                                   'data': {'pe': f'0x{len(pe_section_data):X}', 'mem': f'0x{len(section_data):X}'}})

    for i, (pe_byte, byte) in enumerate(zip(pe_section_data, section_data)):
        if pe_byte != byte:
            suspicious_reasons.append({'reason': 'unmatching_bytes',
                                       'data': {'offset': f'0x{i:X}', 'pe': f'0x{pe_byte:X}', 'mem': f'0x{byte:X}'}})
    if len(suspicious_reasons) != 0:
        return section_name, {'result': 'suspicious', 'reasons': suspicious_reasons}
    return section_name, {'result': 'OK'}


def get_sections(pid: int, process: wintypes.HANDLE, dos_addr) -> list[SectionHeader]:
    c_dosheader = (ctypes.c_ubyte * ctypes.sizeof(DOSHeader))()
    c_outcb = ctypes.c_size_t()
    res = ReadProcessMemory(process, dos_addr, c_dosheader, ctypes.sizeof(c_dosheader), ctypes.byref(c_outcb))
    if 0 == res:
        logger.error(f'[{pid}] Cannot read header from 0x{dos_addr:X}')
        return []

    dosheader = ctypes.cast(c_dosheader, ctypes.POINTER(DOSHeader)).contents
    if dosheader.e_magic != 0x5A4D:
        logger.warning(f'[{pid}] DOS Header at 0x{dos_addr} has invalid signature - 0x{dosheader.e_magic:X}')

    pe_hdr_addr = dos_addr + dosheader.e_lfanew
    c_peheader = (ctypes.c_ubyte * ctypes.sizeof(PEHeader))()
    res = ReadProcessMemory(process, pe_hdr_addr, c_peheader, ctypes.sizeof(c_peheader), ctypes.byref(c_outcb))
    if 0 == res:
        logger.error(f'[{pid}] Cannot read header from 0x{dos_addr:X}')
        return []

    peheader = ctypes.cast(c_peheader, ctypes.POINTER(PEHeader)).contents
    if peheader.Signature != 0x4550:
        logger.warning(f'[{pid}] PE Header at 0x{pe_hdr_addr} has invalid signature - 0x{peheader.Signature:X}')

    section_num = peheader.NumberOfSections
    opt_hdr_size = peheader.SizeOfOptionalHeader
    section_headers_addr = pe_hdr_addr + opt_hdr_size + ctypes.sizeof(PEHeader)
    logger.debug(f'[{pid}] Section addr - 0x{section_headers_addr:X}')

    sections = []
    for i in range(0, section_num):
        section_addr = section_headers_addr + i * ctypes.sizeof(SectionHeader)
        c_section_header = (ctypes.c_ubyte * ctypes.sizeof(SectionHeader))()
        res = ReadProcessMemory(process, section_addr, c_section_header, ctypes.sizeof(c_section_header),
                                ctypes.byref(c_outcb))

        if 0 == res:
            logger.error(f'[{pid}] Cannot read header from 0x{section_addr:X}')
            continue

        section_header = ctypes.cast(c_section_header, ctypes.POINTER(SectionHeader)).contents
        sections.append(section_header)

    return sections


def validate_module(pid: int, process: wintypes.HANDLE, module: wintypes.HMODULE) -> tuple[str, dict]:
    c_modname = ctypes.create_string_buffer(256)
    res = GetModuleFileName(process, module, c_modname, ctypes.sizeof(c_modname))
    use_addr_as_name = False
    if 0 == res:
        logger.warning(f'[{pid}] Cannot get name of module, using its address')
        use_addr_as_name = True

    modpath = c_modname.value
    modname = modpath.rsplit(b'\\')[-1]

    modinfo = MODULEINFO()
    res = GetModuleInformation(process, module, ctypes.byref(modinfo), ctypes.sizeof(modinfo))
    if 0 == res:
        logger.error(f'[{pid}] Cannot get base address of module {modname if not use_addr_as_name else ""}')
        return '', {}

    mod_base = modinfo.lpBaseOfDll
    mod_name = modname if not use_addr_as_name else ''.join("{:02X}".format(x) for x in bytearray(mod_base))

    logger.debug(f'[{pid}] Loading PE for module {mod_name}')
    mod_pe = pefile.PE(modpath)

    results = {}
    for section in get_sections(pid, process, mod_base):
        section_res = validate_section(mod_pe, process, mod_base, section)
        if section_res:
            name, res = section_res
            results[name] = res

    return mod_name, results


def validator_main(pid: int, ctx: Context = None):
    global logger
    if ctx:
        logger = initMultiprocessingLogger(ctx.log_queue, 'MemoryValidator')
    logger.setLevel(logging.CRITICAL)

    logger.debug(f'[{pid}] Begin memory validation for process {pid}')

    process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if 0 == process_handle:
        logger.error(f'[{pid}] Cannot open process handle, err={GetLastError()}')
        return None
    logger.debug(f'[{pid}] Opened process handle')

    c_hmodules = (wintypes.HMODULE * 128)()
    c_cbneeded = wintypes.DWORD()

    res = EnumProcessModules(process_handle, c_hmodules, ctypes.sizeof(c_hmodules), ctypes.byref(c_cbneeded))
    if 0 == res:
        logger.error(f'[{pid}] Cannot retrieve module list, err={GetLastError()}')
        return None
    pmodules = c_hmodules[0:int(c_cbneeded.value / ctypes.sizeof(wintypes.HMODULE))]

    logger.debug(f'[{pid}] Retrieved {len(pmodules)} modules')

    results = {}
    for i, pmodule in enumerate(pmodules):
        if i > 0:
            break
        logger.debug(f'[{pid}] Validating memory of module #{i}')
        name, res = validate_module(pid, process_handle, pmodule)
        name = name.rstrip(b'\x00').decode('ascii')
        results[name] = res

    return results


# if __name__ == '__main__':
#     beg = time.time()
#     res = validator_main(14956)
#     end = time.time()
#     print(res)
#     print(f'Retrieved on {end - beg} seconds')
