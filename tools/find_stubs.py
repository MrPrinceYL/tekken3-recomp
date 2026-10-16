"""Find the PsyQ BIOS call stubs and the startup code in the PS-X EXE and write the symbol
file ApplySymbols.java consumes (addr,name,size,section).

A PsyQ libapi/libc stub is `addiu t2,zero,0xA0|0xB0|0xC0 ; jr t2 ; addiu t1,zero,N`: a jump
into the kernel's function table N. The names are the BIOS kernel's (psx-spx "BIOS Function
Summary"). Usage: python find_stubs.py <SLUS_xxx.xx> <symbols.csv>
"""
import csv
import struct
import sys

A0 = {
    0x00: "open", 0x01: "lseek", 0x02: "read", 0x03: "write", 0x04: "close", 0x05: "ioctl",
    0x06: "exit", 0x07: "isatty", 0x08: "getc", 0x09: "putc", 0x0A: "todigit", 0x0B: "atof",
    0x0C: "strtoul", 0x0D: "strtol", 0x0E: "abs", 0x0F: "labs", 0x10: "atoi", 0x11: "atol",
    0x12: "atob", 0x13: "setjmp", 0x14: "longjmp", 0x15: "strcat", 0x16: "strncat",
    0x17: "strcmp", 0x18: "strncmp", 0x19: "strcpy", 0x1A: "strncpy", 0x1B: "strlen",
    0x1C: "index", 0x1D: "rindex", 0x1E: "strchr", 0x1F: "strrchr", 0x20: "strpbrk",
    0x21: "strspn", 0x22: "strcspn", 0x23: "strtok", 0x24: "strstr", 0x25: "toupper",
    0x26: "tolower", 0x27: "bcopy", 0x28: "bzero", 0x29: "bcmp", 0x2A: "memcpy", 0x2B: "memset",
    0x2C: "memmove", 0x2D: "memcmp", 0x2E: "memchr", 0x2F: "rand", 0x30: "srand", 0x31: "qsort",
    0x32: "strtod", 0x33: "malloc", 0x34: "free", 0x35: "lsearch", 0x36: "bsearch",
    0x37: "calloc", 0x38: "realloc", 0x39: "InitHeap", 0x3A: "_exit", 0x3B: "getchar",
    0x3C: "putchar", 0x3D: "gets", 0x3E: "puts", 0x3F: "printf", 0x40: "SystemErrorUnresolvedException",
    0x41: "LoadTest", 0x42: "Load", 0x43: "Exec", 0x44: "FlushCache", 0x45: "InstallInterruptHandler",
    0x46: "GPU_dw", 0x47: "mem2vram", 0x48: "SendGPUStatus", 0x49: "GPU_cw", 0x4A: "GPU_cwb",
    0x4B: "SendPackets", 0x4C: "sub_4C", 0x4D: "GetGPUStatus", 0x4E: "GPU_sync",
    0x51: "LoadExec", 0x54: "_96_init", 0x55: "_bu_init", 0x56: "_96_remove",
    0x70: "_bu_init", 0x71: "_96_init", 0x72: "_96_remove", 0x78: "CdAsyncSeekL",
    0x7C: "CdAsyncGetStatus", 0x7E: "CdAsyncReadSector", 0x81: "CdAsyncSetMode",
    0x9F: "SetMem", 0xA0: "_boot", 0xA1: "SystemError", 0xA2: "EnqueueCdIntr",
    0xA3: "DequeueCdIntr", 0xA7: "bufs_cb_0", 0xAB: "_card_info", 0xAC: "_card_load",
    0xAD: "_card_auto", 0xAF: "_card_clear",
}
B0 = {
    0x00: "SysMalloc", 0x01: "sys_b0_01", 0x02: "SetRCnt", 0x03: "GetRCnt", 0x04: "StartRCnt",
    0x05: "StopRCnt", 0x06: "ResetRCnt", 0x07: "DeliverEvent", 0x08: "OpenEvent",
    0x09: "CloseEvent", 0x0A: "WaitEvent", 0x0B: "TestEvent", 0x0C: "EnableEvent",
    0x0D: "DisableEvent", 0x0E: "OpenTh", 0x0F: "CloseTh", 0x10: "ChangeTh", 0x12: "InitPAD",
    0x13: "StartPAD", 0x14: "StopPAD", 0x15: "PAD_init", 0x16: "PAD_dr",
    0x17: "ReturnFromException", 0x18: "ResetEntryInt", 0x19: "HookEntryInt",
    0x20: "UnDeliverEvent", 0x32: "open", 0x33: "lseek", 0x34: "read", 0x35: "write",
    0x36: "close", 0x37: "ioctl", 0x38: "exit", 0x39: "isatty", 0x3A: "getc", 0x3B: "putc",
    0x3C: "getchar", 0x3D: "putchar", 0x3E: "gets", 0x3F: "puts", 0x40: "cd", 0x41: "format",
    0x42: "firstfile", 0x43: "nextfile", 0x44: "rename", 0x45: "delete", 0x46: "undelete",
    0x47: "AddDevice", 0x48: "RemoveDevice", 0x49: "PrintInstalledDevices", 0x4A: "InitCARD",
    0x4B: "StartCARD", 0x4C: "StopCARD", 0x4D: "_card_info_subfunc", 0x4E: "_card_write",
    0x4F: "_card_read", 0x50: "_new_card", 0x51: "Krom2RawAdd", 0x54: "_get_errno",
    0x55: "_get_error", 0x56: "GetC0Table", 0x57: "GetB0Table", 0x58: "_card_chan",
    0x59: "testdevice", 0x5B: "ChangeClearPad", 0x5C: "_card_status", 0x5D: "_card_wait",
}
C0 = {
    0x00: "InitRCnt", 0x01: "InitException", 0x02: "SysEnqIntRP", 0x03: "SysDeqIntRP",
    0x04: "get_free_EvCB_slot", 0x05: "get_free_TCB_slot", 0x06: "ExceptionHandler",
    0x07: "InstallExceptionHandlers", 0x08: "SysInitMemory", 0x09: "SysInitKMem",
    0x0A: "ChangeClearRCnt", 0x0B: "SystemError", 0x0C: "InitDefInt", 0x0D: "SetIrqAutoAck",
    0x12: "InstallDevices", 0x13: "FlushStdInOutPut", 0x15: "tty_cdevinput",
    0x16: "tty_cdevscan", 0x17: "tty_circgetc", 0x18: "tty_circputc", 0x19: "ioabort",
    0x1A: "set_card_find_mode", 0x1B: "KernelRedirect", 0x1C: "AdjustA0Table",
    0x1D: "get_card_find_mode",
}
TABLES = {0xA0: A0, 0xB0: B0, 0xC0: C0}


def main():
    """Find the BIOS call stubs in the executable and write symbols.csv."""
    exe = open(sys.argv[1], "rb").read()
    pc0, gp0, base, size = struct.unpack_from("<4I", exe, 0x10)
    d = exe[0x800:0x800 + size]
    w = lambda a: struct.unpack_from("<I", d, a - base)[0]
    rows = [(pc0, "__start", 0, ".text")]
    seen = {}
    for a in range(base, base + size - 12, 4):
        x = w(a)
        # addiu t2,zero,T / ori t2,zero,T ; jr t2 ; addiu t1,zero,N
        if (x & 0xFFFFFF00) in (0x240A0000, 0x340A0000) and (x & 0xFF) in TABLES \
                and w(a + 4) == 0x01400008 and (w(a + 8) & 0xFFFF0000) in (0x24090000, 0x34090000):
            t, n = x & 0xFF, w(a + 8) & 0xFFFF
            base_name = TABLES[t].get(n, f"bios_{t:02X}_{n:02X}")
            name = f"{base_name}"
            if name in seen.values():
                name = f"{base_name}_{t:02X}{n:02X}"
            seen[a] = name
            rows.append((a, name, 12, ".text"))
    with open(sys.argv[2], "w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["addr", "name", "size", "section", "table", "number"])
        for a, name, sz, sec in rows:
            t = n = ""
            if sz == 12:
                x = w(a)
                t, n = f"0x{x & 0xFF:02X}", f"0x{w(a + 8) & 0xFFFF:02X}"
            wr.writerow([f"0x{a:08X}", name, sz, sec, t, n])
    print(f"{len(rows) - 1} BIOS stubs, entry {pc0:#010x}")


if __name__ == "__main__":
    main()
