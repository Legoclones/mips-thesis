from pwn import cyclic

# base class for MIPS sigreturn frames
class MIPS_SigreturnFrame:
    regs = {}
    endian = 'big'      # default to big-endian
    word_size = 4       # default to 32-bit
    frame_size = 0x200  # default frame size

    def __init__(self):
        for reg in self.regs:
            setattr(self, reg.lower(), None)

    def __bytes__(self):
        frame = bytearray(cyclic(self.frame_size))
        for reg, offset in self.regs.items():
            value = getattr(self, reg.lower())
            if value is None:
                continue
            frame[offset:offset+self.word_size] = value.to_bytes(self.word_size, self.endian)
        return bytes(frame)

# MIPS 32-bit o32 little-endian sigreturn frame
class MIPS_o32_LE_SigreturnFrame(MIPS_SigreturnFrame):
    endian = 'little'
    regs = {
        "V0": 0x38,
        "V1": 0x40,
        "A0": 0x48,
        "A1": 0x50,
        "A2": 0x58,
        "A3": 0x60,
        "T0": 0x68,
        "T1": 0x70,
        "T2": 0x78,
        "T3": 0x80,
        "T4": 0x88,
        "T5": 0x90,
        "T6": 0x98,
        "T7": 0xa0,
        "T8": 0xe8,
        "T9": 0xf0,
        "S0": 0xa8,
        "S1": 0xb0,
        "S2": 0xb8,
        "S3": 0xc0,
        "S4": 0xc8,
        "S5": 0xd0,
        "S6": 0xd8,
        "S7": 0xe0,
        "S8": 0x118,
        "GP": 0x108,
        "FP": 0x110,
        "SP": 0x110,
        "RA": 0x120,
        "PC": 0x20
    }

# MIPS 32-bit o32 big-endian sigreturn frame
class MIPS_o32_BE_SigreturnFrame(MIPS_SigreturnFrame):
    regs = {
        "V0": 0xd4,
        "V1": 0xdc,
        "A0": 0xe4,
        "A1": 0xec,
        "A2": 0xf4,
        "A3": 0xfc,
        "T0": 0x104,
        "T1": 0x10c,
        "T2": 0x114,
        "T3": 0x11c,
        "T4": 0x124,
        "T5": 0x12c,
        "T6": 0x134,
        "T7": 0x13c,
        "T8": 0x184,
        "T9": 0x18c,
        "S0": 0x144,
        "S1": 0x14c,
        "S2": 0x154,
        "S3": 0x15c,
        "S4": 0x164,
        "S5": 0x16c,
        "S6": 0x174,
        "S7": 0x17c,
        "S8": 0x1b4,
        "GP": 0x1a4,
        "FP": 0x1ac,
        "SP": 0x1ac,
        "RA": 0x1bc,
        "PC": 0xbc,
    }

class MIPS_n32_BE_SigreturnFrame(MIPS_SigreturnFrame):
    frame_size = 0x300
    word_size = 8
    regs = {'AT': 184, 'V0': 192, 'V1': 200, 'A0': 208, 'A1': 216, 'A2': 224, 'A3': 232, 'A4': 240, 'A5': 248, 'A6': 256, 'A7': 264, 'T0': 272, 'T1': 280, 'T2': 288, 'T3': 296, 'S0': 304, 'S1': 312, 'S2': 320, 'S3': 328, 'S4': 336, 'S5': 344, 'S6': 352, 'S7': 360, 'T8': 368, 'T9': 376, 'K0': 384, 'K1': 392, 'GP': 400, 'SP': 408, 'S8': 416, 'RA': 424, 'PC': 752}

class MIPS_n32_LE_SigreturnFrame(MIPS_n32_BE_SigreturnFrame):
    endian = 'little'

class MIPS_n64_BE_SigreturnFrame(MIPS_SigreturnFrame):
    frame_size = 0x330
    word_size = 8
    regs = {
        "V0": 0xd0,
        "V1": 0xd8,
        "A0": 0xe0,
        "A1": 0xe8,
        "A2": 0xf0,
        "A3": 0xf8,
        "T0": 0x120,
        "T1": 0x128,
        "T2": 0x130,
        "T3": 0x138,
        "T8": 0x180,
        "T9": 0x188,
        "S0": 0x140,
        "S1": 0x148,
        "S2": 0x150,
        "S3": 0x158,
        "S4": 0x160,
        "S5": 0x168,
        "S6": 0x170,
        "S7": 0x178,
        "S8": 0x1b0,
        "GP": 0x1a0,
        "FP": 0x1a8,
        "SP": 0x1a8,
        "RA": 0x1b8,
        "PC": 0x300,
    }

class MIPS_n64_LE_SigreturnFrame(MIPS_n64_BE_SigreturnFrame):
    endian = 'little'