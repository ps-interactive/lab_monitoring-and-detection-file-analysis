private rule shellcode_injection {
    strings:
        $virt_alloc = { 41 B9 04 00 00 00 E8 0E 45 01 00 48 89 C3 }
        $memmove = { 48 89 C3 48 89 C1 48 89 FA 49 89 F0 }
        $virt_protect = { 41 B8 20 00 00 00 E8 E5 44 01 00 85 C0 }
        $wait_for = { 48 89 C1 BA FF FF FF FF E8 B1 44 01 00 }
        $load_shellcode = { C7 44 24 30 03 00 00 00 48 8D 05 2C 73 01 00 }
        
    condition:
        all of them
}

rule roguewave_implant {
    meta:
        author = "elusivethreat"
        filetype = "Win32 EXE"
        date = "01/01/2024"
        version = "1.0"
    
    strings:
        $b = "rust_panic"
        $b1 = "AddVectoredExceptionHandler"
        $b2 = "SetThreadStackGuarantee"

    condition:
        all of ($b*)
        and shellcode_injection
}