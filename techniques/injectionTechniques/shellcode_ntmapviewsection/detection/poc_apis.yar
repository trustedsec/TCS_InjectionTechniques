rule ntmapviewsection_APIs
{
    meta:
        author = "Leo Bastidas"
        description = "Detects the compiled version of shellcode_ntmapviewsection source code based on Windows APIs used"

    strings:
        $s1 = "WSAStartup" wide ascii
        $s2 = "gethostbyname" wide ascii
        $s3 = "WSACleanup" wide ascii
        $s4 = "socket" wide ascii
        $s5 = "connect" wide ascii
        $s6 = "send" wide ascii
        $s7 = "recv" wide ascii
        $s8 = "closesocket" wide ascii
        $s9 = "VirtualAlloc" wide ascii
        $s10 = "VirtualFree" wide ascii
        $s11 = "NtCreateSection" wide ascii
        $s12 = "NtMapViewOfSection" wide ascii
        $s13 = "GetCurrentProcess" wide ascii
        $s14 = "OpenProcess" wide ascii
        $s15 = "RtlCreateUserThread" wide ascii

    condition:
        5 of them
}