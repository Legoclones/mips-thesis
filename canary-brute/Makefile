.PHONY: all mips x86 clean pull
default: all


### ENVIRONMENTAL VARIABLES ###
FILE="canary-brute.c"
OUTDIR=./binaries
GEN_OPTIONS=-fstack-protector-all # enable canaries on this one
MIPS32R6LE = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mipsel32r6-glibc mipsel-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS32R2LE = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mipsel32r2-glibc mipsel-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R6LE_N32 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mipsel64r6-glibc-n32 mips64el-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R2LE_N32 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mipsel64r2-glibc-n32 mips64el-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R6LE_N64 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mipsel64r6-glibc-n64 mips64el-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R2LE_N64 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mipsel64r2-glibc-n64 mips64el-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS32R6 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mips32r6-glibc mips-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS32R2 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mips32r2-glibc mips-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R6_N32 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mips64r6-glibc-n32 mips64-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R2_N32 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mips64r2-glibc-n32 mips64-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R6_N64 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mips64r6-glibc-n64 mips64-linux-gcc ${FILE} $(GEN_OPTIONS)
MIPS64R2_N64 = docker run -it --rm -v ${PWD}:/workdir legoclones/mips-compile:mips64r2-glibc-n64 mips64-linux-gcc ${FILE} $(GEN_OPTIONS)
PIE=-fPIE -pie
NO_PIE="-no-pie"
STATIC="-static"
O32="-mabi=32"
N32="-mabi=n32"
N64="-mabi=64"

X86 = docker run -it --rm -v ${PWD}:/workdir gcc:15.1.0-bookworm gcc /workdir/${FILE} $(GEN_OPTIONS) -Wl,-z,relro,-z,now
X86_OUTDIR = /workdir/x86_binaries
###	   END ENVIRON	   ###

all: mips x86

mips:
	$(MIPS32R2)       $(NO_PIE)           $(O32) -o $(OUTDIR)/mips32r2_no_pie_o32
	$(MIPS32R2)       $(PIE)              $(O32) -o $(OUTDIR)/mips32r2_pie_o32
	$(MIPS32R2)       $(NO_PIE) $(STATIC) $(O32) -o $(OUTDIR)/mips32r2_static_o32
	$(MIPS32R2LE)     $(NO_PIE)           $(O32) -o $(OUTDIR)/mips32r2le_no_pie_o32
	$(MIPS32R2LE)     $(PIE)              $(O32) -o $(OUTDIR)/mips32r2le_pie_o32
	$(MIPS32R2LE)     $(NO_PIE) $(STATIC) $(O32) -o $(OUTDIR)/mips32r2le_static_o32
	$(MIPS32R6)       $(NO_PIE)           $(O32) -o $(OUTDIR)/mips32r6_no_pie_o32
	$(MIPS32R6)       $(PIE)              $(O32) -o $(OUTDIR)/mips32r6_pie_o32
	$(MIPS32R6)       $(NO_PIE) $(STATIC) $(O32) -o $(OUTDIR)/mips32r6_static_o32
	$(MIPS32R6LE)     $(NO_PIE)           $(O32) -o $(OUTDIR)/mips32r6le_no_pie_o32
	$(MIPS32R6LE)     $(PIE)              $(O32) -o $(OUTDIR)/mips32r6le_pie_o32
	$(MIPS32R6LE)     $(NO_PIE) $(STATIC) $(O32) -o $(OUTDIR)/mips32r6le_static_o32
	$(MIPS64R2_N32)   $(NO_PIE)           $(N32) -o $(OUTDIR)/mips64r2_no_pie_n32
	$(MIPS64R2_N64)   $(NO_PIE)           $(N64) -o $(OUTDIR)/mips64r2_no_pie_n64
	$(MIPS64R2_N32)   $(PIE)              $(N32) -o $(OUTDIR)/mips64r2_pie_n32
	$(MIPS64R2_N64)   $(PIE)              $(N64) -o $(OUTDIR)/mips64r2_pie_n64
	$(MIPS64R2_N32)   $(NO_PIE) $(STATIC) $(N32) -o $(OUTDIR)/mips64r2_static_n32
	$(MIPS64R2_N64)   $(NO_PIE) $(STATIC) $(N64) -o $(OUTDIR)/mips64r2_static_n64
	$(MIPS64R2LE_N32) $(NO_PIE)           $(N32) -o $(OUTDIR)/mips64r2le_no_pie_n32
	$(MIPS64R2LE_N64) $(NO_PIE)           $(N64) -o $(OUTDIR)/mips64r2le_no_pie_n64
	$(MIPS64R2LE_N32) $(PIE)              $(N32) -o $(OUTDIR)/mips64r2le_pie_n32
	$(MIPS64R2LE_N64) $(PIE)              $(N64) -o $(OUTDIR)/mips64r2le_pie_n64
	$(MIPS64R2LE_N32) $(NO_PIE) $(STATIC) $(N32) -o $(OUTDIR)/mips64r2le_static_n32
	$(MIPS64R2LE_N64) $(NO_PIE) $(STATIC) $(N64) -o $(OUTDIR)/mips64r2le_static_n64
	$(MIPS64R6_N32)   $(NO_PIE)           $(N32) -o $(OUTDIR)/mips64r6_no_pie_n32
	$(MIPS64R6_N64)   $(NO_PIE)           $(N64) -o $(OUTDIR)/mips64r6_no_pie_n64
	$(MIPS64R6_N32)   $(PIE)              $(N32) -o $(OUTDIR)/mips64r6_pie_n32
	$(MIPS64R6_N64)   $(PIE)              $(N64) -o $(OUTDIR)/mips64r6_pie_n64
	$(MIPS64R6_N32)   $(NO_PIE) $(STATIC) $(N32) -o $(OUTDIR)/mips64r6_static_n32
	$(MIPS64R6_N64)   $(NO_PIE) $(STATIC) $(N64) -o $(OUTDIR)/mips64r6_static_n64
	$(MIPS64R6LE_N32) $(NO_PIE)           $(N32) -o $(OUTDIR)/mips64r6le_no_pie_n32
	$(MIPS64R6LE_N64) $(NO_PIE)           $(N64) -o $(OUTDIR)/mips64r6le_no_pie_n64
	$(MIPS64R6LE_N32) $(PIE)              $(N32) -o $(OUTDIR)/mips64r6le_pie_n32
	$(MIPS64R6LE_N64) $(PIE)              $(N64) -o $(OUTDIR)/mips64r6le_pie_n64
	$(MIPS64R6LE_N32) $(NO_PIE) $(STATIC) $(N32) -o $(OUTDIR)/mips64r6le_static_n32
	$(MIPS64R6LE_N64) $(NO_PIE) $(STATIC) $(N64) -o $(OUTDIR)/mips64r6le_static_n64

x86:
	$(X86) $(NO_PIE)           -o $(X86_OUTDIR)/x86_no_pie
	$(X86) $(PIE)              -o $(X86_OUTDIR)/x86_pie
	$(X86) $(NO_PIE) $(STATIC) -o $(X86_OUTDIR)/x86_static

clean:
	rm -rf $(OUTDIR)/* $(X86_OUTDIR)/*

pull:
	docker pull legoclones/mips-compile:mipsel32r6-glibc
	docker pull legoclones/mips-compile:mipsel32r2-glibc
	docker pull legoclones/mips-compile:mipsel64r6-glibc-n32
	docker pull legoclones/mips-compile:mipsel64r2-glibc-n32
	docker pull legoclones/mips-compile:mipsel64r6-glibc-n64
	docker pull legoclones/mips-compile:mipsel64r2-glibc-n64
	docker pull legoclones/mips-compile:mips32r6-glibc
	docker pull legoclones/mips-compile:mips32r2-glibc
	docker pull legoclones/mips-compile:mips64r6-glibc-n32
	docker pull legoclones/mips-compile:mips64r2-glibc-n32
	docker pull legoclones/mips-compile:mips64r6-glibc-n64
	docker pull legoclones/mips-compile:mips64r2-glibc-n64
	docker pull gcc:15.1.0-bookworm
	
	docker pull legoclones/mips-pwn:mipsel32r6-glibc
	docker pull legoclones/mips-pwn:mipsel32r2-glibc
	docker pull legoclones/mips-pwn:mipsel64r6-glibc-n32
	docker pull legoclones/mips-pwn:mipsel64r2-glibc-n32
	docker pull legoclones/mips-pwn:mipsel64r6-glibc-n64
	docker pull legoclones/mips-pwn:mipsel64r2-glibc-n64
	docker pull legoclones/mips-pwn:mips32r6-glibc
	docker pull legoclones/mips-pwn:mips32r2-glibc
	docker pull legoclones/mips-pwn:mips64r6-glibc-n32
	docker pull legoclones/mips-pwn:mips64r2-glibc-n32
	docker pull legoclones/mips-pwn:mips64r6-glibc-n64
	docker pull legoclones/mips-pwn:mips64r2-glibc-n64