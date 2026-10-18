/*
    YARA rules for QBot MitB hooks.
    Target: 7fc3f5e06bbaad459af71d3c0d28c51b7802546984f886f14a1b12a779fff6f8
    https://www.virustotal.com/gui/file/7fc3f5e06bbaad459af71d3c0d28c51b7802546984f886f14a1b12a779fff6f8/details
*/

rule qbot_install_hooks
{
    meta:
        description = "Iterates encrypted hook table, resolves APIs via GetModuleHandleA/GetProcAddress, installs inline hooks."
        family = "QBot"
        author = "gemesa@protonmail.com"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_10002902_install_hooks"

    strings:
        /*
        10002920 ff 15 48        CALL       dword ptr [->KERNEL32.DLL::GetModuleHandleA]     = 00023870
                 80 01 10
        10002926 8b f8           MOV        EDI,param_1
        ...
        10002945 ff 15 44        CALL       dword ptr [->KERNEL32.DLL::GetProcAddress]       = 0002385e
                 80 01 10

        */
        $resolve_pair = {
            FF 15 [4]
            8B F8
            [1-16]
            FF 15
        }

        /*
                                     LAB_1000295e                                    XREF[3]:     1000291d(j), 10002932(j), 
                                                                                          10002941(j)  
        1000295e 83 c6 15        ADD        ESI,0x15
        10002961 4b              DEC        EBX
        10002962 75 ad           JNZ        LAB_10002911
        */
        $loop_stride = {
            83 C6 15
            4B
            75 ??
        }

        /*
        10002930 85 ff           TEST       EDI,EDI
        10002932 74 2a           JZ         LAB_1000295e
        10002934 8b 46 04        MOV        param_1,dword ptr [ESI + 0x4]
        */
        $null_gate_module = {
            85 FF
            74 ??
            8B 46 04
        }

        /*
                                     LAB_10002911                                    XREF[1]:     10002962(j)  
        10002911 8b 06           MOV        param_1,dword ptr [ESI]
        10002913 e8 ad 1e        CALL       FUN_100147c5_decrypt_string                      undefined * FUN_100147c5_decrypt
                 01 00
        10002918 89 45 fc        MOV        dword ptr [EBP + local_8],param_1
        1000291b 85 c0           TEST       param_1,param_1
        1000291d 74 3f           JZ         LAB_1000295e
        */
        $struct_access = {
            8B 06
            E8 [4]
            [2-8]
            85 C0
            74 ??
        }

    condition:
        uint16(0) == 0x5A4D and
        $resolve_pair and
        $loop_stride and
        2 of ($null_gate_module, $struct_access)
}

rule qbot_install_chrome_hooks
{
    meta:
        description = "Parses Chrome PE header, scans .text section for signature matches, installs inline hooks."
        family = "QBot"
        author = "gemesa@protonmail.com"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_10002a7b_install_chrome_hooks"

    strings:
        $dot_text = ".text" ascii

        /*
        10002aca 81 3f 50        CMP        dword ptr [EDI],0x4550
                 45 00 00
        */
        $pe_sig_check = {
            81 3F 50 45 00 00
        }

        /*
                                     LAB_10002b02                                    XREF[1]:     10002c7e(j)  
        10002b02 68 3c 82        PUSH       s_.text_1001823c                                 = ".text"
                 01 10
        10002b07 ff 75 f4        PUSH       dword ptr [EBP + local_10]
        10002b0a ff 15 38        CALL       dword ptr [->KERNEL32.DLL::lstrcmpA]             = 00023832
                 80 01 10
        10002b10 85 c0           TEST       EAX,EAX
        */
        $strcmp_text = {
            68 [4]
            FF 75 ??
            FF 15 [4]
            85 C0
        }

        /*
        10002bb9 81 c6 0c        ADD        ESI,0x30c
                 03 00 00
        */
        $sig_stride = {
            81 C6 0C 03 00 00
        }

        /*
        10002b2f 81 c6 02        ADD        ESI,0x102
                 01 00 00
        */
        $sig_offset = {
            81 C6 02 01 00 00
        }

        /*
        10002ac5 8b 78 3c        MOV        EDI,dword ptr [EAX + 0x3c]
        10002ac8 03 f8           ADD        EDI,EAX
        */
        $elfanew = {
            8B 78 3C
            03 F8
        }

        /*
        10002c37 e8 f2 00        CALL       FUN_10002d2e                                     undefined4 FUN_10002d2e(void * p
                 00 00
        10002c3c 85 c0           TEST       EAX,EAX
        10002c3e 78 44           JS         LAB_10002c84
        */
        $hook_and_check = {
            E8 [4]
            85 C0
            78 ??
        }

    condition:
        uint16(0) == 0x5A4D and
        $dot_text and
        $pe_sig_check and
        $elfanew and
        3 of ($strcmp_text, $sig_stride, $sig_offset, $hook_and_check)
}

rule qbot_chrome_boringssl_signature_table
{
    meta:
        description = "QBot Chrome BoringSSL inline hook signature table (20 version-specific byte patterns for locating SSL/TLS functions in chrome.dll .text section)."
        family = "QBot"
        author = "gemesa@protonmail.com"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "DAT_10024d38_chrome_sig_table, FUN_10002c8c_install_chrome_hooks_w"
        note = "The sig table is referenced in the hook install function, so the function can be located by following the sig table references."

    strings:
        /*
                                 DAT_10024d38_chrome_sig_table                   XREF[1]:     FUN_10001000_return_chrome_sig_t
        10024d38 90              ??         90h
        10024d39 00              ??         00h
        10024d3a 55              ??         55h    U
        10024d3b 89              ??         89h
        ...
        */
        $chrome_sig_entry0_a = {
            90 00                               // len = 0x90
            55 89 e5 53 57 56 83 ec 08 a1       // prologue
            aa aa aa aa                         // wildcard
            8b 7d 08 31 e8 89 45 f0
            8b 47 18
            c7 80 9c 00 00 00 00 00 00 00
        }

        /*
        10024e3a 60              ??         60h    `
        10024e3b 00              ??         00h
        10024e3c 55              ??         55h    U
        10024e3d 89              ??         89h
        ...
        */
        $chrome_sig_entry0_b = {
            60 00                               // len = 0x60
            55 89 e5 57 56 8b 7d 08             // prologue
            83 7f 50 00
            74 20
            68 31 04 00 00
            68 aa aa aa aa                      // push <wildcard>
            6a 42
            6a 00
            6a 10
        }

        /*
        10024f3c 5e              ??         5Eh    ^
        10024f3d 00              ??         00h
        10024f3e 55              ??         55h    U
        10024f3f 89              ??         89h
        ...
        */
        $chrome_sig_entry0_c = {
            5e 00                               // len = 0x5e
            55 89 e5 53 56 8b 75 0c 31 db       // prologue
            85 f6
            0f aa aa aa aa aa                   // conditional jump <wildcard>
        }

        /*
        10025044 8d              ??         8Dh
        10025045 00              ??         00h
        10025046 55              ??         55h    U
        10025047 89              ??         89h
        ...
        */
        $chrome_sig_entry1_a = {
            8d 00                               // len = 0x8d
            55 89 e5 53 57 56 50                // prologue
            8b 45 0c 8b 75 08
            c6 00 00
            8b 46 18
            83 b8 90 00 00 00 00
        }

        // Add further entries here if necessary.

    condition:
        2 of ($chrome_sig_entry*)
}

rule qbot_hook_table_firefox_ssl
{
    meta:
        description = "QBot Firefox SSL hook table (PR_Read, PR_Write, PR_Close, PR_OpenTCPSocket via nss3.dll and nspr4.dll)."
        family = "QBot"
        author = "gemesa@protonmail.com"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_10002cf3_install_firefox_ssl_hooks"
        note = "The hook table is referenced in the hook install function, so the function can be located by following the hook table references."

    strings:
        /*
                             nss3.dll
                             DAT_10024bf8_firefox_ssl_hooks                  XREF[2]:     FUN_100026dc:10002891(*), 
                                                                                          FUN_10002cf3_install_firefox_ssl
        10024bf8 f5 1c 00 00     ddw        1CF5h
                             PR_OpenTCPSocket
        10024bfc 2e 09 00 00     ddw        92Eh
        10024c00 ef a6 00 10     ddw        1000A6EFh
        10024c04 f4 8a 02 10     ddw        10028AF4h
        10024c08 00 00 00        ??[5]
                 00 00
        */
        $firefox_nss3 = {
            f5 1c 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            f5 1c 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            f5 1c 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            f5 1c 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
        }
        /*
                                nspr4.dll
        10024c4c e4 05 00 00     ddw        5E4h
                             PR_OpenTCPSocket
        10024c50 2e 09 00 00     ddw        92Eh
        10024c54 ef a6 00 10     ddw        1000A6EFh
        10024c58 f4 8a 02 10     ddw        10028AF4h
        10024c5c 00 00 00        ??[5]
                 00 00
        */
        $firefox_nspr4 = {
            e4 05 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            e4 05 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            e4 05 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            e4 05 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
        }

    condition:
        $firefox_nss3 and $firefox_nspr4
}

rule qbot_hook_table_wininet
{
    meta:
        description = "QBot WinInet hook table (10 entries hooking HttpSendRequest, InternetReadFile, HttpOpenRequest, etc.)."
        family = "QBot"
        author = "gemesa@protonmail.com"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_10002a02_install_wininet_hooks"
        note = "The hook table is referenced in the hook install function, so the function can be located by following the hook table references."

    strings:
        /*
                                     wininet.dll
                             DAT_10024b20_wininet_hooks                      XREF[3]:     FUN_100026dc:10002812(*), 
                                                                                          FUN_10002a02_install_wininet_hoo
                                                                                          FUN_10002d56_init_hook_slots:100
        10024b20 c5 21 00 00     ddw        21C5h
                             HttpSendRequestA
        10024b24 d7 24 00 00     ddw        24D7h
        10024b28 af df 00 10     ddw        1000DFAFh
        10024b2c 9c aa 02 10     ddw        1002AA9Ch
        10024b30 00 00 00        ??[5]
                 00 00
        */
        $wininet_table = {
            c5 21 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            c5 21 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            c5 21 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
        }

    condition:
        $wininet_table
}

rule qbot_hook_table_core_0
{
    meta:
        description = "QBot core_0 hook table (WSAConnect, connect, WSASend, send). "
        family = "QBot"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_100029f5_install_core_hooks"
        note = "The hook table is referenced in the hook install function, so the function can be located by following the hook table references."

    strings:
        /*
        10024a05 6a 1d 00 00     ddw        1D6Ah
                             WSAConnect
        10024a09 08 06 00 00     ddw        608h
        10024a0d 1f f0 00 10     ddw        1000F01Fh
        10024a11 48 b4 02 10     ddw        1002B448h
        10024a15 00 00 00        ??[5]
                 00 00
        */
        $ws2_table = {
            6a 1d 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            6a 1d 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            6a 1d 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            6a 1d 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
        }

    condition:
        $ws2_table
}

rule qbot_hook_table_core_1
{
    meta:
        description = "QBot core_1 hook table (DnsQuery_A, DnsQuery_W, Query_Main)."
        family = "QBot"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_100029f5_install_core_hooks"
        note = "The hook table is referenced in the hook install function, so the function can be located by following the hook table references."

    strings:
        /*
        10024a59 23 09 00 00     ddw        923h
                             DnsQuery_A
        10024a5d 1c 33 00 00     ddw        331Ch
        10024a61 91 25 00 10     ddw        10002591h
        10024a65 68 8a 02 10     ddw        10028A68h
        10024a69 00 00 00        ??[5]
                 00 00
        */
        $dns_table = {
            23 09 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            23 09 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            23 09 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
        }

    condition:
        $dns_table
}

rule qbot_hook_table_messageloop
{
    meta:
        description = "QBot message loop hook table (GetMessageA/W, PeekMessageA/W)."
        family = "QBot"
        hash = "4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089"
        reference = "FUN_10002a1c_install_message_loop_hooks"
        note = "The hook table is referenced in the hook install function, so the function can be located by following the hook table references."

    strings:
        /*
                                     user32.dll
                             DAT_10024ac8_message_loop_hooks                 XREF[2]:     FUN_10002a1c_install_message_loo
                                                                                          FUN_10002d56_init_hook_slots:100
        10024ac8 8e 33 00 00     ddw        338Eh
                             GetMessageA
        10024acc 0e 27 00 00     ddw        270Eh
        10024ad0 57 8f 00 10     ddw        10008F57h
        10024ad4 e4 8a 02 10     ddw        10028AE4h
        10024ad8 00 00 00        ??[5]
                 00 00
        */
        $msgloop_table = {
            8e 33 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            8e 33 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            8e 33 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
            8e 33 00 00 ?? ?? 00 00 ?? ?? 00 10 ?? ?? 02 10 00 00 00 00 00
        }

    condition:
        $msgloop_table
}
