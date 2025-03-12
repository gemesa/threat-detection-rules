import "pe"

rule hancitor_unpacked {
  meta:
    description = "Hancitor (unpacked)"
    author = "Andras Gemes"
    date = "2025-02-18"
    sha256 = "3b0e94042c0387a80f2f59ae38e8bdf1cd026a328c1b641b777403ae575ba0f0"
    ref1 = "https://shadowshell.io/hancitor-loader"
    ref2 = "https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"

  strings:
    $1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
    $2 = "http://api.ipify.org"
    $3 = "0.0.0.0"
    /*
      undefined4 __cdecl mw_check_cmd(char *param_1)

      {
        char *local_8;
        
        local_8 = s_ncdrleb_100041f0;
        if (param_1[1] == ':') {
          for (; *local_8 != '\0'; local_8 = local_8 + 1) {
            if (*local_8 == *param_1) {
              return 1;
            }
          }
        }
        return 0;
      }
    */
    $4 = "ncdrleb"
    $5 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
    $6 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
    $7 = "Rundll32.exe %s, start"
    $8 = "svchost.exe"
    $9 = "explorer.exe"
    $10 = "SystemRoot"
    $11 = "\\System32\\svchost.exe"
    $12 = "MASSLoader.dll"
    /*
                            **************************************************************
                            * Export Name Pointers                                       *
                            **************************************************************
                            DAT_100043e0                                    XREF[1]:     100043d0(*)  
      100043e0 fb 43 00 00     ibo32      100043fb                                         = "FCQNEAXPXCR"
      100043e4 07 44 00 00     ibo32      10004407                                         = "GSDEAEBPVHTSM"
    */
    $13 = "FCQNEAXPXCR"
    $14 = "GSDEAEBPVHTSM"

    /*
      10002d1c 8d 4d fc        LEA        ECX=>local_8,[EBP + -0x4]
      10002d1f 51              PUSH       ECX
      10002d20 6a 00           PUSH       0x0
      10002d22 6a 00           PUSH       0x0
      10002d24 68 04 80        PUSH       CALG_SHA1 // 0x8004
               00 00
      10002d29 8b 55 f8        MOV        EDX,dword ptr [EBP + local_c]
      10002d2c 52              PUSH       EDX
      10002d2d ff 15 0c        CALL       dword ptr [->ADVAPI32.DLL::CryptCreateHash]      = 00004bde
               40 00 10
    */
    $CryptCreateHash = { 8d 4d fc 51 6a 00 6a 00 68 04 80 00 00 8b 55 f8 52 ff 15 }

    /*
      10002d57 8d 45 f4        LEA        EAX=>local_10,[EBP + -0xc]
      10002d5a 50              PUSH       EAX
      10002d5b 8b 4d ec        MOV        ECX,dword ptr [EBP + local_18]
      10002d5e 51              PUSH       ECX
      10002d5f 8b 55 fc        MOV        EDX,dword ptr [EBP + local_8]
      10002d62 52              PUSH       EDX
      10002d63 68 01 68        PUSH       CALG_RC4 // 0x6801
               00 00
      10002d68 8b 45 f8        MOV        EAX,dword ptr [EBP + local_c]
      10002d6b 50              PUSH       EAX
      10002d6c ff 15 18        CALL       dword ptr [->ADVAPI32.DLL::CryptDeriveKey]       = 00004baa
               40 00 10

    */
    $CryptDeriveKey = { 8d 45 f4 50 8b 4d ec 51 8b 55 fc 52 68 01 68 00 00 8b 45 f8 50 ff 15 }

  condition:
    pe.is_pe and 8 of them
}
