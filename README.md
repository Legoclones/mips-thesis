# Stack-Based Exploit Development Techniques in MIPS Architectures


## Stack-Based Exploit Development Techniques
| ID | Family | Technique Name | ACE | Bypass Mitigations | Increases Capabilities |
|----|---------------|---------------------------------------|---|---|---|
| 1  | Code Reuse    | Partial Overwrite                     |   | X |   |
| 2  | Code Reuse    | ret2mprotect                          |   | X |   |
| 3  | Code Reuse    | ret2plt                               |   | X |   |
| 4  | Code Reuse    | ret2syscall                           | X |   |   |
| 5  | Code Reuse    | ret2system                            | X |   |   |
| 6  | Code Reuse    | ret2win                               | X |   |   |
| 7  | Code Reuse    | SigReturn-Oriented Programming (SROP) |   |   | X |
| 8  | Code Reuse    | Stack Pivoting                        |   |   | X |
| 9  | Shellcode     | ret2reg                               |   | X |   |
| 10 | Shellcode     | ret2shellcode                         | X |   |   |
| 11 | Canary Bypass | fork() Canary Brute Force             |   | X |   |