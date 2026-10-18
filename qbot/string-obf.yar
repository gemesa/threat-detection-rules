/*
    YARA rules for QBot string decryptor.
    Target: 4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089
    https://www.virustotal.com/gui/file/4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089/details
*/

rule qbot_string_decryptor
{
    meta:
        description = "QBot rolling XOR string decryptor. Resolves DLL names, API names and config strings."
        author = "gemesa@protonmail.com"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_100147c5_decrypt_string"

    strings:
        // Length-finding loop. Scan blob for null terminator.

        /*
                                     LAB_10014805                                    XREF[1]:     10014818(j)  
        10014805 8b d1           MOV        EDX,ECX
        10014807 83 e2 3f        AND        EDX,0x3f
        1001480a 8a 92 c0        MOV        DL,byte ptr [EDX + DAT_100244c0]                 = 5Ah    Z
                 44 02 10
        10014810 32 14 08        XOR        DL,byte ptr [param_1 + ECX*0x1]
        10014813 74 07           JZ         LAB_1001481c
        10014815 41              INC        ECX
        10014816 3b ce           CMP        ECX,ESI
        10014818 72 eb           JC         LAB_10014805
        */

        $null_scan = {
            8B D1
            83 E2 3F
            8A 92 ?? ?? ?? ??
            32 14 08
            74 07
            41
            3B CE
            72 EB
        }

        // Decrypt loop. XOR each byte with rolling key.

        /*
                                     LAB_10014844                                    XREF[1]:     1001485c(j)  
        10014844 8d 0c 10        LEA        ECX,[param_1 + EDX*0x1]
        10014847 8d 1c 0f        LEA        EBX,[EDI + ECX*0x1]
        1001484a 83 e3 3f        AND        EBX,0x3f
        1001484d 8a 9b c0        MOV        BL,byte ptr [EBX + DAT_100244c0]                 = 5Ah    Z
                 44 02 10
        10014853 32 1c 16        XOR        BL,byte ptr [ESI + EDX*0x1]
        10014856 42              INC        EDX
        10014857 88 19           MOV        byte ptr [ECX],BL
        */
        $decrypt_loop = {
            8D 0C 10
            8D 1C 0F
            83 E3 3F
            8A 9B ?? ?? ?? ??
            32 1C 16
            42
            88 19
        }

        // Blob size constant 0x36F4 (max encrypted blob length).

        /*
                                     LAB_100147fa                                    XREF[2]:     100147d8(j), 100147f1(j)  
        100147fa be f4 36        MOV        ESI,0x36f4
                 00 00
        */
        $blob_size = { BE F4 36 00 00 }

    condition:
        ($null_scan and $decrypt_loop) or
        ($null_scan and $blob_size)
}
