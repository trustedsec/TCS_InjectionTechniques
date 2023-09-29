rule network_ntmapviewsection
{
    meta:
        author = "Leo Bastidas"
        description = "Detects the compiled version of shellcode_ntmapviewsection source code"

    strings:
        $s1 = "Failed to setup socket" wide ascii
        $s2 = "http://mal_download.com/spawn_calc.x64.sc" wide ascii
        $s3 = "USAGE: %s <target PID>" wide ascii
        $s4 = "Content-Length:" wide ascii
        $s5 = "GET / HTTP/1.1" wide ascii
        $s6 = "GET %s HTTP/1.1" wide ascii
        $s7 = "Host: %s" wide ascii

    condition:
        2 of them
}