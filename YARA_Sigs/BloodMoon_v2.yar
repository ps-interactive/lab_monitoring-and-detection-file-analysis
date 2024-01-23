
private rule moduleLoader {
    strings:
        $ntdll = "NTDLL.DLL" wide ascii
        $virt_alloc = "VirtualAlloc"
        $virt_protect = "VirtualProtect"
        $injection_call = { 45 33 C9 45 33 C0 33 D2 49 ?? ?? FF D6 }
        $injection_api =  { C7 45 ?? 52 00 74 00 C7 45 ?? 6C 00 43 00 C7 45 ?? 72 00 65 00 C7 45 ?? 61 00 74 00 C7 45 } // RtlCreate
    
    condition:
        all of them

}


rule keylogger_module {
    strings:
        $event = "MSTeams_Support_01_16"
        $event2 = "OpenEventA"
        $find_window = { FF 15 ?? ?? 00 00 48 8B C8 BA 01 00 00 00 }
        $set_hook = { 48 8D 15 ?? ?? FF FF 41 8D 49 0D FF 15 ?? ?? 00 00 }
        $get_msg = { 48 8D 4C 24 78 FF 15 ?? ?? 00 00 }

    condition:
        4 of them
}


rule screencapture_module {
    strings:
        $a = "GdipSaveImageToFile"
        $a1 = "BitBlt"
        $a2 = "SelectObject"
        $a3 = "ReleaseDC"
        $a4 = "GdiplusShutdown"
        $a5 = "M.blog"
        $a6 = { 48 89 7C 24 38 48 8d 4C 24 28 E8 04 F8 ?? ?? B9 60 EA 00 00 } // call screen_shot -> sleep
        $a7 = "MSTeams_Support_01_17"


    condition:
        6 of them
}

rule lunar_transport_v1 {
    
    meta:
        author = "elusivethreat"
        filetype = "Win32 DLL"
        date = "01/01/2024"
        version = "1.0"
    
    strings:
        $a = "\\AppData\\Local\\Microsoft\\Teams\\current\\ffmpeg.dat"	// Encrypted shellcode
        $a2 = "CreateFileA"
        $a3 = "GetFileSize"
        $a4 = "ReadFile"
		
    condition:
        uint16(0) == 0x5A4D
        and filesize < 100000
		and all of ($a*)

}


rule bloodmoon_v2_implant {
    meta:
        author = "elusivethreat"
        filetype = "Win32 DLL or sRDI shellcode"
        date = "01/01/2024"
        version = "1.0"

    strings:
        $b =  { E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00 BA 40 D8 24 E1 }    // sRDI stub
        $b2 = { 80 34 30 ?? 48 FF C0 48 3D ?? ?? ?? ?? }                            // XOR Decrypt
        $b3 = { 48 89 5C 24 10 48 89 74 24 18 55 57 41 54 }                         // HTTP/C2 Module
        $b4 = { B8 50 50 50 50 09 19 D9 }                                           // Encrypted module (unk_18000B460)
    
    condition:
        all of ($b*)
        and moduleLoader 

}