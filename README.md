# Stack-Based Exploit Development Techniques in MIPS Architectures
This repo houses the proof of concept source code, executables, and exploit code used in my Masters Thesis from Brigham Young University (BYU) titled "Stack-Based Exploit Development Techniques in MIPS Architectures".

> Memory corruption vulnerabilities in binary executables represent a serious threat to software security, particularly in embedded and IoT (Internet of Things) devices that commonly use the MIPS architecture. While exploit development techniques for x86 are well-documented in academic literature, little systematic work exists on how those techniques translate to other architectures such as MIPS. This research addresses that gap by evaluating eleven stack-based exploit development techniques, originally designed in the context of the x86 architecture, for their applicability to MIPS architectures. For each technique, vulnerable C code was written and compiled into both x86 and a set of 36 MIPS variants covering multiple ABIs (Application Binary Interfaces), releases, endianness configurations, and PIE (Position-Independent Code) and static compilation settings. Proof of concept exploit code was developed for each variant, and each technique was classified as *Fully Applicable*, *May Be Applicable With MIPS-Specific Adaptations*, or *Not Applicable*. Of the eleven techniques evaluated, the majority were found to be applicable to MIPS with varying degrees of MIPS-specific knowledge required. Three techniques or subtechniques were found to be not applicable within the scope of this research, with the root causes traced to MIPS leaf function behavior, MIPS stub mechanics, and the interaction between full RELRO (Relocation Read-Only) and the lazy binding resolution mechanism. The most pervasive source of MIPS-specific adaptation was the `$gp` register initialization behavior in function prologues, which affects any technique that redirects execution to a function in a different memory segment. These findings suggest that an exploit developer familiar with stack-based exploitation on x86 can transfer the majority of their knowledge to MIPS, provided they develop familiarity with MIPS-specific calling conventions, ABI-defined register saving behavior, and the `$gp` initialization sequence in MIPS function prologues. All proof of concept executables and exploit code are open-sourced to support reproducibility and future research.

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
