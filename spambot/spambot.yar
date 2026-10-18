/*
    YARA rules for spambot malware family.
    Target: 36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6
    https://www.virustotal.com/gui/file/36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6/detection
*/

rule spambot_xor_cipher
{
    meta:
        description = "Detects the XOR cipher function that derives its key from MD5(\"UNREGISTERED\")."
        author = "gemesa@protonmail.com"
        hash = "36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6"
        reference = "FUN_004680d0_xor_cipher"

    strings:
        $key_string = "UNREGISTERED" ascii

        /*
        004680e6 6a 0c           PUSH       12
        004680e8 68 ac 73        PUSH       s_UNREGISTERED_005673ac                          = "UNREGISTERED"
                 56 00
        004680ed 8d 45 ec        LEA        EAX=>key,[EBP + -0x14]
        004680f0 50              PUSH       EAX
        004680f1 e8 0a 38        CALL       FUN_0044b900_md5_hash                            undefined FUN_0044b900_md5_hash(
                 fe ff
        */
        $md5_call = { 6A 0C 68 ?? ?? ?? ?? 8D 45 EC 50 E8 }

        /*
        00468116 83 e0 0f        AND        EAX,0xf
        */
        $xor_mask = { 83 E? 0F }

    condition:
        uint16(0) == 0x5A4D and all of them
}

rule spambot_blowfish_config
{
    meta:
        description = "Detects Blowfish-ECB config decryption from PE resource."
        author = "gemesa@protonmail.com"
        hash = "36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6"
        reference = "FUN_00472da0_bot_main (key init + resource load)"

    strings:
        /*
        00472e70 c6 45 e0 07     MOV        byte ptr [EBP + key[0]],0x7
        00472e74 c6 45 e1 54     MOV        byte ptr [EBP + key[1]],0x54
        00472e78 c6 45 e2 08     MOV        byte ptr [EBP + key[2]],0x8
        00472e7c c6 45 e3 d5     MOV        byte ptr [EBP + key[3]],0xd5
        00472e80 c6 45 e4 67     MOV        byte ptr [EBP + key[4]],0x67
        00472e84 c6 45 e5 85     MOV        byte ptr [EBP + key[5]],0x85
        00472e88 c6 45 e6 9e     MOV        byte ptr [EBP + key[6]],0x9e
        00472e8c c6 45 e7 e2     MOV        byte ptr [EBP + key[7]],0xe2
        00472e90 c6 45 e8 af     MOV        byte ptr [EBP + key[8]],0xaf
        00472e94 c6 45 e9 e3     MOV        byte ptr [EBP + key[9]],0xe3
        00472e98 c6 45 ea c6     MOV        byte ptr [EBP + key[10]],0xc6
        00472e9c c6 45 eb a9     MOV        byte ptr [EBP + key[11]],0xa9
        00472ea0 c6 45 ec 8f     MOV        byte ptr [EBP + key[12]],0x8f
        00472ea4 c6 45 ed 3b     MOV        byte ptr [EBP + key[13]],0x3b
        00472ea8 c6 45 ee 0c     MOV        byte ptr [EBP + key[14]],0xc
        00472eac c6 45 ef 5b     MOV        byte ptr [EBP + key[15]],0x5b
        */
        $key_init = { C6 45 ?? 07 C6 45 ?? 54 C6 45 ?? 08 C6 45 ?? D5 }

        /*
                                CRYPT_Blowfish_p_init                           XREF[1]:     FUN_00421d20_blowfish_key_schedu
        005605c0 88 6a 3f        db[32]
                 24 d3 08 
                 a3 85 2e 
           005605c0 [0]            88h, 6Ah, 3Fh, 24h,
           005605c4 [4]            D3h,  8h, A3h, 85h,
           005605c8 [8]            2Eh, 8Ah, 19h, 13h,
           005605cc [12]           44h, 73h, 70h,  3h,
           005605d0 [16]           22h, 38h,  9h, A4h,
           005605d4 [20]           D0h, 31h, 9Fh, 29h,
           005605d8 [24]           98h, FAh, 2Eh,  8h,
           005605dc [28]           89h, 6Ch, 4Eh, ECh
        */
        $bf_parray = { 88 6A 3F 24 D3 08 A3 85 }

        /*
                             LAB_00472def                                    XREF[1]:     00472de9(j)  
        00472def 6a 0a           PUSH       DAT_0000000a
        00472df1 68 e2 00        PUSH       DAT_000000e2
                 00 00
        00472df6 6a 00           PUSH       0x0
                             0xe2 = resource ID
                             0xa = RT_RCDATA = Application-defined resource (raw data).
        00472df8 ff 15 30        CALL       dword ptr [->KERNEL32.DLL::FindResourceA]        = 0019fa9e
                 01 56 00
        */
        $find_resource = { 6A 0A 68 ?? ?? ?? ?? 6A 00 FF 15 }

    condition:
        uint16(0) == 0x5A4D and $bf_parray and ($key_init or $find_resource)
}

rule spambot_zipcrypto
{
    meta:
        description = "Detects ZipCrypto (Traditional PKWARE Encryption) initialization."
        author = "gemesa@protonmail.com"
        hash = "36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6"
        reference = "FUN_0047f7b0_zip_and_add_file, FUN_0047eb70_zipcrypto_update_keys"

    strings:
        /*
                             initialize the 3 ZipCrypto keys (PKWARE spec section 6.1.5)
        0047fda5 c7 44 10        MOV        dword ptr [EAX + EDX*0x1 + 0x30],0x12345678
                 30 78 56 
                 34 12
        0047fdad b9 04 00        MOV        this,0x4
                 00 00
        0047fdb2 c1 e1 00        SHL        this,0x0
        0047fdb5 8b 95 68        MOV        EDX,dword ptr [EBP + local_49c]
                 fb ff ff
        0047fdbb c7 44 0a        MOV        dword ptr [EDX + this*0x1 + 0x30],0x23456789
                 30 89 67 
                 45 23
        0047fdc3 b8 04 00        MOV        EAX,0x4
                 00 00
        0047fdc8 d1 e0           SHL        EAX,0x1
        0047fdca 8b 8d 68        MOV        this,dword ptr [EBP + local_49c]
                 fb ff ff
        0047fdd0 c7 44 01        MOV        dword ptr [this + EAX*0x1 + 0x30],0x34567890
                 30 90 78 
                 56 34
        */
        $zip_keys = { 78 56 34 12 [0-32] 89 67 45 23 [0-32] 90 78 56 34 }

        /*
        0047ebec 69 04 0a        IMUL       EAX,dword ptr [EDX + ECX*0x1],0x8088405
                 05 84 08 08
        0047ebf3 83 c0 01        ADD        EAX,0x1
        */
        $update_keys = { 05 84 08 08 }

    condition:
        uint16(0) == 0x5A4D and all of them
}

rule spambot_hmac_md5
{
    meta:
        description = "Detects the custom HMAC-MD5 implementation used for CRAM-MD5 authentication."
        author = "gemesa@protonmail.com"
        hash = "36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6"
        reference = "FUN_0044bf00_hmac_md5_core"

    strings:
        /*
        0044bca4 c7 04 01        MOV        dword ptr [ECX + EAX*0x1],0x67452301
                 01 23 45 67
        0044bcab ba 04 00        MOV        EDX,0x4
                 00 00
        0044bcb0 c1 e2 00        SHL        EDX,0x0
        0044bcb3 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
        0044bcb6 c7 04 10        MOV        dword ptr [EAX + EDX*0x1],0xefcdab89
                 89 ab cd ef
        0044bcbd b9 04 00        MOV        ECX,0x4
                 00 00
        0044bcc2 d1 e1           SHL        ECX,0x1
        0044bcc4 8b 55 08        MOV        EDX,dword ptr [EBP + param_1]
        0044bcc7 c7 04 0a        MOV        dword ptr [EDX + ECX*0x1],0x98badcfe
                 fe dc ba 98
        0044bcce b8 04 00        MOV        EAX,0x4
                 00 00
        0044bcd3 6b c8 03        IMUL       ECX,EAX,0x3
        0044bcd6 8b 55 08        MOV        EDX,dword ptr [EBP + param_1]
        0044bcd9 c7 04 0a        MOV        dword ptr [EDX + ECX*0x1],0x10325476
                 76 54 32 10
        */
        $md5_init_A = { 01 23 45 67 }
        $md5_init_B = { 89 AB CD EF }
        $md5_init_C = { FE DC BA 98 }
        $md5_init_D = { 76 54 32 10 }

        /*
        0044bfd1 8b 8d b0        MOV        ECX,dword ptr [EBP + local_154]
                 fe ff ff
        0044bfd7 0f b6 54        MOVZX      EDX,byte ptr [EBP + ECX*0x1 + -0x58]
                 0d a8
        0044bfdc 83 f2 36        XOR        EDX,0x36
        0044bfdf 8b 85 b0        MOV        EAX,dword ptr [EBP + local_154]
                 fe ff ff
        0044bfe5 88 54 05 a8     MOV        byte ptr [EBP + EAX*0x1 + -0x58],DL
        0044bfe9 8b 8d b0        MOV        ECX,dword ptr [EBP + local_154]
                 fe ff ff
        0044bfef 0f b6 94        MOVZX      EDX,byte ptr [EBP + ECX*0x1 + 0xffffff64]
                 0d 64 ff 
                 ff ff
        0044bff7 83 f2 5c        XOR        EDX,0x5c
        */
        $ipad = { 0F B6 54 0D ?? 83 F2 36 }
        $opad = { 0F B6 94 0D ?? ?? ?? ?? 83 F2 5C }

        /*
                             s_CRAM-MD5_00563640                             XREF[1]:     FUN_004437d0_state_machine:00444
        00563640 43 52 41        ds         "CRAM-MD5"
                 4d 2d 4d 
                 44 35 00
        */
        $cram_md5 = "CRAM-MD5" ascii

    condition:
        uint16(0) == 0x5A4D and
        all of ($md5_init_*) and
        $ipad and
        $opad and
        $cram_md5
}

rule spambot_dkim_domainkeys
{
    meta:
        description = "Detects the DomainKeys and DKIM email signing with rsa-sha1."
        author = "gemesa@protonmail.com"
        hash = "36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6"
        reference = "FUN_00433f40_domainkeys_sign, FUN_00431880_dkim_sign"

    strings:
        $dk_sig   = "DomainKey-Signature: a=rsa-sha1" ascii
        $dkim_sig = "DKIM-Signature:" ascii
        $rsa_sha1 = "rsa-sha1" ascii
        $dk_query = "_domainkey.%s" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule spambot_weak_prng
{
    meta:
        description = "Detects the weak PRNG (MSVC rand with time(NULL) seed) used for ZipCrypto headers."
        author = "gemesa@protonmail.com"
        hash = "36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6"
        reference = "FUN_00542fc7_rand, FUN_0044e700_weak_random"

    strings:
        /*
                             FUN_00542fc7_rand                               XREF[2]:     FUN_0044e700_weak_random:0044e70
                                                                                          FUN_0047f7b0_zip_and_add_file:00
        00542fc7 e8 a7 63        CALL       __getptd                                         _ptiddata __getptd(void)
                 00 00
        00542fcc 69 48 14        IMUL       ECX,dword ptr [EAX + 0x14],0x343fd
                 fd 43 03 00
        00542fd3 81 c1 c3        ADD        ECX,0x269ec3
                 9e 26 00
        00542fd9 89 48 14        MOV        dword ptr [EAX + 0x14],ECX
        00542fdc c1 e9 10        SHR        ECX,0x10
        00542fdf 81 e1 ff        AND        ECX,0x7fff
                 7f 00 00
        00542fe5 8b c1           MOV        EAX,ECX
        00542fe7 c3              RET
        */
        $rand_mul = { FD 43 03 00 }
        $rand_add = { C3 9E 26 00 }

        /*
                             FUN_0044e700_weak_random                        XREF[20]:    FUN_0044d9b0:0044da7c(c), 
        ...
        0044e700 55              PUSH       EBP
        0044e701 8b ec           MOV        EBP,ESP
        0044e703 51              PUSH       ECX
        0044e704 e8 be 48        CALL       FUN_00542fc7_rand                                uint FUN_00542fc7_rand(void)
                 0f 00
        0044e709 0f af 45 08     IMUL       EAX,dword ptr [EBP + param_1]
        0044e70d 99              CDQ
        0044e70e b9 ff 7f        MOV        ECX,0x7fff
                 00 00
        0044e713 f7 f9           IDIV       ECX
        */
        $divisor = { FF 7F 00 00 }

    condition:
        uint16(0) == 0x5A4D and all of them
}
