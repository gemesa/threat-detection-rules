import "pe"

rule hancitor_packed {
  meta:
    description = "Hancitor (packed)"
    author = "Andras Gemes"
    date = "2025-02-18"
    sha256 = "efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"
    ref1 = "https://shadowshell.io/hancitor-loader"
    ref2 = "https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"

  strings:
    /*
                            **************************************************************
                            * Export Name Pointers                                       *
                            **************************************************************
                            DAT_1005d3d0                                    XREF[1]:     1005d3c0(*)  
      1005d3d0 e6 d3 05 00     ibo32      1005d3e6                                         = "Broke"
      1005d3d4 ec d3 05 00     ibo32      1005d3ec                                         = "Necessaryearly"
    */
    $1 = "Broke"
    $2 = "Necessaryearly"

    /*
      1005ac6b 68 88 0e        PUSH       0xe88
               00 00
      1005ac70 68 10 75        PUSH       DAT_10007510                                     = E1h
               00 10
      1005ac75 68 18 09        PUSH       DAT_10060918
               06 10
      1005ac7a e8 f1 ca        CALL       _memcpy                                          void * _memcpy(void * _Dst, void
               fb ff
    */
    $_memcpy = { 68 88 0e 00 00 68 [4] 68 [4] e8 }

    /*
      1005b526 68 83 05        PUSH       0x583
               00 00
      1005b52b 8d 54 24 34     LEA        EDX=>local_b10,[ESP + 0x34]
      1005b52f 52              PUSH       EDX
      1005b530 ff 15 18        CALL       dword ptr [->KERNEL32.DLL::GetSystemDirectoryW]  = 0005c73a
               10 00 10
    */
    $GetSystemDirectoryW = { 68 83 05 00 00 8d 54 24 34 52 ff 15 }

    /*
      1005a3ad 68 83 05        PUSH       0x583
               00 00
      1005a3b2 68 20 fc        PUSH       DAT_1005fc20
               05 10
      1005a3b7 6a 00           PUSH       0x0
      1005a3b9 ff 15 28        CALL       dword ptr [->KERNEL32.DLL::GetModuleFileNameW]   = 0005c778
               10 00 10
    */
    $GetModuleFileNameW = { 68 83 05 00 00 68 [4] 6a 00 ff 15 }

    /*
      1005a401 a1 20 20        MOV        EAX,[DAT_10072020]
               07 10
      1005a406 8b 15 94        MOV        EDX,dword ptr [DAT_1005f094]                     = 000A9AD5h
               f0 05 10
      1005a40c 68 14 09        PUSH       DAT_10060914
               06 10
      1005a411 6a 40           PUSH       0x40
      1005a413 68 00 51        PUSH       0x5100
               00 00
      1005a418 50              PUSH       EAX
      1005a419 6a ff           PUSH       -0x1
      1005a41b 8d 9c 16        LEA        EBX,[ESI + EDX*0x1 + 0x10f]
               0f 01 00 00
      1005a422 ff 15 38        CALL       dword ptr [->KERNEL32.DLL::VirtualProtectEx]     = 0005c7c6
               10 00 10
    */
    $VirtualProtectEx = { a1 [4] 8b 15 [4] 68 [4] 6a 40 68 00 51 00 00 50 6a ff 8d 9c 16 0f 01 00 00 ff 15 }

    /*
      1005a4f9 2a c2           SUB        AL,DL
      1005a4fb 68 20 fc        PUSH       DAT_1005fc20
               05 10
      1005a500 02 c3           ADD        AL,BL
      1005a502 68 83 05        PUSH       0x583
               00 00
      1005a507 a2 68 f0        MOV        [DAT_1005f068],AL                                = C8h
               05 10
      1005a50c ff 15 30        CALL       dword ptr [->KERNEL32.DLL::GetCurrentDirectoryW] = 0005c79c
               10 00 10
    */
    $GetCurrentDirectoryW = { 2a c2 68 [4] 02 c3 68 83 05 00 00 a2 [4] ff 15 }

    /*
      10028e6f 8a da           MOV        BL,DL
      10028e71 2a d8           SUB        BL,AL
      10028e73 02 d9           ADD        BL,CL
      10028e75 80 c3 19        ADD        BL,0x19
      10028e78 0f b6 cb        MOVZX      ECX,BL
      10028e7b 2b ca           SUB        ECX,EDX
      10028e7d 0f b7 d6        MOVZX      EDX,SI
      10028e80 03 d1           ADD        EDX,ECX
      10028e82 89 15 64        MOV        dword ptr [DAT_1005f064],EDX                     = 000BE899h
               f0 05 10
    */
    $decrypt1 = { 8a da 2a d8 02 d9 80 c3 19 0f b6 cb 2b ca 0f b7 d6 03 d1 89 15 }

    /*
      10028e88 8b 1d b8        MOV        EBX,dword ptr [DAT_1005f0b8]                     = 00000051h
               f0 05 10
      10028e8e 81 c7 d0        ADD        EDI,0x10864d0
               64 08 01
      10028e94 8a cb           MOV        CL,BL
      10028e96 2a c8           SUB        CL,AL
      10028e98 89 7d 00        MOV        dword ptr [EBP],EDI
      10028e9b 80 c1 17        ADD        CL,0x17
      10028e9e 83 c5 04        ADD        EBP,0x4
      10028ea1 83 6c 24        SUB        dword ptr [ESP + local_c],0x1
               10 01
      10028ea6 89 3d 24        MOV        dword ptr [DAT_10072024],EDI
               20 07 10
    */
    $decrypt2 = { 8b 1d [4] 81 c7 d0 64 08 01 8a cb 2a c8 89 7d 00 80 c1 17 83 c5 04 83 6c 24 10 01 89 3d }

  condition:
    pe.is_pe and 5 of them
}
