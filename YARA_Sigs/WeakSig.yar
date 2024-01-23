rule shellcode_injection {
   meta:
        author = "Anonymous"
        filetype = "Basic Shellcode Injection Technique"
        date = "01/01/2024"
        version = "0.1"
    strings:
        $a = "VirtualAlloc"
        $a1 = "CreateRemoteThread"
        $a2 = "RtlMoveMemory"
        $a3 = "VirtualProtect"

    condition:
        3 of them
}

