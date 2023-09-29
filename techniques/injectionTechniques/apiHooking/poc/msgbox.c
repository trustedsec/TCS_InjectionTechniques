#include<windows.h>
#include<stdio.h>

int print_test()
{
    __asm__("push %rcx");
    __asm__("push %rdx");
    __asm__("push %r8");
    __asm__("push %r9");
    __asm__("sub $0x20, %rsp");

    printf("This is a test to see if we jumped here instead\n");
    __asm__("add $0x20, %rsp");
    __asm__("pop %r9");
    __asm__("pop %r8");
    __asm__("pop %rdx");
    __asm__("pop %rcx");
    __asm__("add $0x30, %rsp");
    __asm__("pop %rbp");

    __asm__("nop");
    __asm__("nop");

    int x = 1;
    x = x + 3;
    x = x * 4;
    x = x - 20;
    return x;
}

int main( int argc, char* argv[] )
{
    int msgboxID = MessageBox( NULL, "this is a test", "Are you sure?", MB_CANCELTRYCONTINUE);
    void* msgbox_ptr = &MessageBox;
    unsigned char orig[0x100] = {0};
    unsigned char fixup[0x10] = {0};
    unsigned char patch[0x10] = {0};
    DWORD oldProtect = 0;

    // copy messagebox first 11 bytes to call later
	// This is ugly to reset the stack and jump to the real MsgBox. Works 
	// because we are dereferensning teh IAT's MSGBOX pointer and jumping to that
	/* 
		0:  48 8b 05 33 6e 00 00    mov    rax,QWORD PTR [rip+0x6e33]        # 0x6e3a
		7:  48 83 c0 07             add    rax,0x7
		b:  ff e0                   jmp    rax
	*/
    memcpy( orig, msgbox_ptr, 0x07);
    memcpy( orig+0x7,  "\x48\x8b\x05\x33\x6e\x00\x00", 0x7); 
    memcpy( orig+0xe, "\x48\x83\xc0\x07\xff\xe0\x00", 0x7);

    printf("print_test addr 0x%p\n", &print_test);
    printf("messageBox 0x%p\n", msgbox_ptr);

    // applying the hook 
	// "push *print_test; ret;"
    memcpy(patch, "\x68", 1);
    *((DWORD*)&patch[1]) = (DWORD*)print_test;
    memcpy(patch+5, "\xc3\x90", 2);

    // applying the hook code
    VirtualProtect( msgbox_ptr, 0x10, 0x04, &oldProtect); // 0x04 PAGE_READWRITE
    memcpy(msgbox_ptr, patch, 7);
    VirtualProtect( msgbox_ptr, 0x10, oldProtect, &oldProtect); 

    // Patching print_test to apply original code and jump back to MessageBox
    oldProtect = 0;
    VirtualProtect( print_test+0x14, 0x10, 0x40, &oldProtect); // 0x04 PAGE_READWRITE
    memcpy( print_test+0x2f, orig, 0x21 );
    VirtualProtect( print_test+0x14, 0x10, oldProtect, &oldProtect); 

    //Calling the test 
    msgboxID = MessageBox( NULL, "this is the second test", "Are you sure?", MB_CANCELTRYCONTINUE);
}
