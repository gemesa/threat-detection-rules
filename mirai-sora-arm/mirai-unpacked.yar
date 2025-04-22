import "elf"

rule mirai_sora_unpacked_arm {
  meta:
    description = "Mirai SORA unpacked (ARM)"
    author = "Andras Gemes"
    date = "2025-04-04"
    sha256 = "ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"
    ref1 = "https://shadowshell.io/mirai-sora-botnet"
    ref2 = "https://bazaar.abuse.ch/sample/ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"

  strings:
    // C2
    $1 = "154.7.253.207"
    // config encryption key
    $2 = { af fb de de }
    // SORA: applet not found
    $3 = { 07 1b 06 15 6e 74 35 24 24 38 31 20 74 3a 3b 20 74 32 3b 21 3a 30 54 00 }
    // /bin/busybox SORA
    $4 = { 7b 36 3d 3a 7b 36 21 27 2d 36 3b 2c 74 07 1b 06 15 54 00 00 }
    // Connected To CNC
    $5 = { 17 3b 3a 3a 31 37 20 31 30 74 00 3b 74 17 1a 17 54 00 00 00 }
    // /dev/watchdog
    $6 = { 7b 30 31 22 7b 23 35 20 37 3c 30 3b 33 54 00 }
    // /dev/misc/watchdog
    $7 = { 7b 30 31 22 7b 39 3d 27 37 7b 23 35 20 37 3c 30 3b 33 54 00 }
    // C2 port number: 1312 (0x520)
    $8 = { 51 74 00 00 }
    // ogin
    $9 = { 3b 33 3d 3a 54 00 }
    // enter
    $10 = { 31 3a 20 31 26 54 00 }
    // enable
    $11 = { 31 3a 35 36 38 31 54 00 }
    // system
    $12 = { 27 2d 27 20 31 39 54 00 }
    // sh
    $13 = { 27 3c 54 00 }
    // shell
    $14 = { 27 3c 31 38 38 54 00 }
    // ncorrect
    $15 = { 3a 37 3b 26 26 31 37 20 54 00 }
    // /proc/
    $16 = { 7b 24 26 3b 37 7b 54 00 }
    // /exe
    $17 = { 7b 31 2c 31 54 00 }
    // .anime
    $18 = { 7a 35 3a 3d 39 31 54 00 }
    // credential decryption function
    /*
        0000ff98 00 20 a0 e3     mov        r2,#0x0
                             LAB_0000ff9c                                    XREF[1]:     0000ffb0(j)  
        0000ff9c 06 30 d2 e7     ldrb       r3,[r2,r6]
        0000ffa0 54 30 23 e2     eor        r3,r3,#0x54
        0000ffa4 06 30 c2 e7     strb       r3,[r2,r6]
        0000ffa8 01 20 82 e2     add        r2,r2,#0x1
        0000ffac 02 00 57 e1     cmp        r7,r2
        0000ffb0 f9 ff ff 1a     bne        LAB_0000ff9c
    */
    $19 = { 00 20 a0 e3 06 30 d2 e7 54 30 23 e2 06 30 c2 e7 01 20 82 e2 02 00 57 e1 ?? ?? ?? 1a }
    // config decryption function
    /*
        00013268 00 c0 a0 e3     mov        r12,#0x0
                             LAB_0001326c                                    XREF[1]:     000132c0(j)  
        0001326c 00 20 9e e5     ldr        r2,[lr,#0x0]=>DAT_00020e64                       = ??
        00013270 02 30 dc e7     ldrb       r3,[r12,r2]
        00013274 03 30 20 e0     eor        r3,r0,r3
        00013278 02 30 cc e7     strb       r3,[r12,r2]
        0001327c 00 10 9e e5     ldr        r1,[lr,#0x0]=>DAT_00020e64                       = ??
        00013280 01 30 dc e7     ldrb       r3,[r12,r1]
        00013284 03 30 26 e0     eor        r3,r6,r3
        00013288 01 30 cc e7     strb       r3,[r12,r1]
        0001328c 00 20 9e e5     ldr        r2,[lr,#0x0]=>DAT_00020e64                       = ??
        00013290 02 30 dc e7     ldrb       r3,[r12,r2]
        00013294 03 30 25 e0     eor        r3,r5,r3
        00013298 02 30 cc e7     strb       r3,[r12,r2]
        0001329c 00 10 9e e5     ldr        r1,[lr,#0x0]=>DAT_00020e64                       = ??
        000132a0 01 30 dc e7     ldrb       r3,[r12,r1]
        000132a4 03 30 24 e0     eor        r3,r4,r3
        000132a8 01 30 cc e7     strb       r3,[r12,r1]
        000132ac 04 20 de e5     ldrb       r2,[lr,#0x4]=>DAT_00020e68                       = ??
        000132b0 01 30 d7 e5     ldrb       r3,[r7,#0x1]=>DAT_00020e69                       = ??
        000132b4 01 c0 8c e2     add        r12,r12,#0x1
        000132b8 03 24 82 e1     orr        r2,r2,r3, lsl #0x8
        000132bc 0c 00 52 e1     cmp        r2,r12
        000132c0 e9 ff ff ca     bgt        LAB_0001326c
    */
    $20 = { 00 c0 a0 e3 00 20 9e e5 02 30 dc e7 03 30 20 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 26 e0 01 30 cc e7 00 20 9e e5 02 30 dc e7 03 30 25 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 24 e0 01 30 cc e7 04 20 de e5 01 30 d7 e5 01 c0 8c e2 03 24 82 e1 0c 00 52 e1 ?? ?? ?? ca }

  condition:
    defined(elf.type) and elf.machine == elf.EM_ARM and 13 of them
}
