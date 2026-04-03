# Stack-Based Exploit Development Techniques in MIPS Architectures
This repo houses the proof of concept source code, executables, and exploit code used in my Masters Thesis from Brigham Young University (BYU) titled "Stack-Based Exploit Development Techniques in MIPS Architectures".

> abstract

## Organization
Each folder contains the following items:
- `binaries/`
    - An executable for each applicable MIPS variant is compiled and stored here
- `solves/`
    - Proof of concept exploit code for each MIPS variant is stored here
- `x86_binaries/`
    - Proof of concept exploit code for x86 executables is stored here
- `x86_solves/`
    - x86 executables demonstrating the tehcnique are compiled and stored here
- `Makefile`
    - Running `make` or `make all` compiles the C code into each MIPS and x86 variant using Docker containers
    - Other `make` targets include `mips` (only compiles C code into MIPS), `x86` (only compiles C code into x86), `clean` (deletes all old executables), and `pull` (pulls all needed Docker containers for compilation, 1 per variant)
- `<technique>.c`
    - The source code vulnerable to a stack-based buffer overflow that can be exploited with the technique

## Stack-Based Exploit Development Techniques
| ID | Family | Technique Name | ACE | Bypass Mitigations | Increases Capabilities |
|----|---------------|--------------------------------------------------|---|---|---|
| 1  | Code Reuse    | [Partial Overwrite](./partial-overwrite/)        |   | X |   |
| 2  | Code Reuse    | [ret2mprotect](./ret2mprotect/)                  |   | X |   |
| 3  | Code Reuse    | [ret2plt](./ret2plt/)                            |   | X |   |
| 4  | Code Reuse    | [ret2syscall](./ret2syscall/)                    | X |   |   |
| 5  | Code Reuse    | [ret2system](./ret2system/)                      | X |   |   |
| 6  | Code Reuse    | [ret2win](./ret2win/)                            | X |   |   |
| 7  | Code Reuse    | [SigReturn-Oriented Programming (SROP)](./srop/) |   |   | X |
| 8  | Code Reuse    | [Stack Pivoting](./stack-pivoting/)              |   |   | X |
| 9  | Shellcode     | [ret2reg](./ret2reg/)                            |   | X |   |
| 10 | Shellcode     | [ret2shellcode](./ret2shellcode/)                | X |   |   |
| 11 | Canary Bypass | [`fork()` Canary Brute Force](./canary-brute/)   |   | X |   |