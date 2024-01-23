// Improved version of LunarTransport loader

private rule moduleLoader {
    strings:
        $ntdll = "NTDLL.DLL" wide ascii
        $virt_protect = "VirtualProtect"
        $virt_alloc = "VirtualAlloc"
        $injection_call = { FC FF FF 48 89 44 24 20 00 00 00 00 FF D3 }
        $injection_api =  { C7 45 ?? 52 00 74 00 C7 45 ?? 6C 00 43 00 C7 45 ?? 72 00 65 00 C7 45 ?? 61 00 74 00 C7 45 } // RtlCreate
    condition:
        3 of them
}

private rule coffeeBreak {
    strings:
        $a = "HeapReAlloc"
        $a2 = "HeapAlloc"
        $a3 = { B9 F4 01 00 00 B3 05 FF 15 18 1C 00 00 }    // Sleep loop
        $a4 = { 8B CF F7 E7 C1 EA 02 8D 04 92 2B C8 74 17 } // Setup during ReAlloc
        $a5 = { FF C7 88 1E 81 FF F4 01 00 00 7C B5 }       // Are we done?
    
    condition:
        all of them
}

rule lunar_stealth_loader {
    meta:
        author = "elusivethreat"
        filetype = "Win32 EXE or sRDI shellcode"
        date = "01/01/2024"
        version = "1.0"
    
    strings:
        $a2 = { 80 34 ?? ?? 48 FF C0 48 3D ?? ?? ?? ?? }         // XOR Decrypt
        $a3 = { B3 5B 5B 5B 5B 02 12 D2 93 13 DA 9A 78 50 }      // Encrypted Falcon9 start
    
    condition:
    all of ($a*)
    and moduleLoader
    and coffeeBreak

}
