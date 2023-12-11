# Stager in C/C++

My first implementation of C/C++ stager for a sliver shellcode.
Downloads a Base64-encoded and AES-encrypted shellcode from remote HTTP-server, opens another process, injects the shellcode to a new process and then executes the shellcode. Uses SysWhispers2 under the hood
