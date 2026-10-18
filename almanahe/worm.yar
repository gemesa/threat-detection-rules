/*
    YARA rules for process injection TTPs.
    Target: f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad
    https://www.virustotal.com/gui/file/f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad/details
    
*/

rule thread_execution_hijacking_suspended_browser
{
    meta:
        description = "Detects thread execution hijacking via suspended browser process."
        author = "gemesa@protonmail.com"
        hash = "f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad"
        mitre_attack = "T1055.003"
        reference = "FUN_10002096_hijack_thread_inject_shellcode, FUN_10002232_create_suspended_browser"

    strings:
        // Hijacking API sequence.
        $api_CreateProcessA     = "CreateProcessA" ascii
        $api_GetThreadContext   = "GetThreadContext" ascii
        $api_SetThreadContext   = "SetThreadContext" ascii
        $api_VirtualAllocEx     = "VirtualAllocEx" ascii
        $api_WriteProcessMemory = "WriteProcessMemory" ascii
        $api_ResumeThread       = "ResumeThread" ascii

        // Default browser in registry.
        $reg_htmlfile = "htmlfile\\shell\\open\\command" ascii nocase

        // Setting ContextFlags CONTEXT_FULL (0x10007) before GetThreadContext.
        /*
        100020c9 c7 85 08        MOV        dword ptr [EBP + local_2fc],0x10007
                 fd ff ff 
                 07 00 01 00
        100020d3 ff 15 fc        CALL       dword ptr [->KERNEL32.DLL::GetThreadContext]     = 000086da
                 60 00 10
        */
        $context_full = { C7 4? ?? 07 00 01 00 }

        /*
        100020d9 6a 40           PUSH       PAGE_EXECUTE_READWRITE
                             MEM_COMMIT: 0x00001000
                             MEM_RESERVE: 0x00002000
        100020db 68 00 30        PUSH       0x3000
                 00 00
        100020e0 68 00 04        PUSH       0x400
                 00 00
        100020e5 6a 00           PUSH       0x0
        100020e7 ff 75 08        PUSH       dword ptr [EBP + param_1]
        100020ea ff 15 00        CALL       dword ptr [->KERNEL32.DLL::VirtualAllocEx]       = 000086c8
                 61 00 10
        */
        $mem_alloc_rwx = { 6A 40 68 00 30 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        (
            // Full hijacking pattern (all 6 APIs).
            all of ($api_*)
            or
            // Key APIs with browser target indicator.
            (4 of ($api_*) and $reg_htmlfile)
            or
            // Context manipulation with RWX allocation.
            ($api_GetThreadContext and $api_SetThreadContext and $context_full and $mem_alloc_rwx and $api_WriteProcessMemory)
        )
}

rule APC_injection_explorer_LoadLibrary
{
    meta:
        description = "Detects APC injection into explorer.exe threads using QueueUserAPC with LoadLibrary."
        author = "gemesa@protonmail.com"
        hash = "f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad"
        mitre_attack = "T1055.004"
        reference = "FUN_10003919_apc_inject_into_explorer, FUN_100039fb_apc_injection_entry"

    strings:
        // APC injection APIs.
        $api_QueueUserAPC             = "QueueUserAPC" ascii
        $api_VirtualAllocEx           = "VirtualAllocEx" ascii
        $api_WriteProcessMemory       = "WriteProcessMemory" ascii
        $api_OpenProcess              = "OpenProcess" ascii
        $api_OpenThread               = "OpenThread" ascii

        // Thread/process enumeration via Toolhelp32.
        $api_CreateToolhelp32Snapshot = "CreateToolhelp32Snapshot" ascii
        $api_Thread32First            = "Thread32First" ascii
        $api_Thread32Next             = "Thread32Next" ascii
        $api_Process32First           = "Process32First" ascii
        $api_Process32Next            = "Process32Next" ascii

        // Target.
        $target_explorer = "explorer.exe" ascii nocase

        // Privilege escalation.
        $priv_debug = "SeDebugPrivilege" ascii

        // Mutexes.
        $mutex1 = "PNP#DMUTEX#1#DL5" ascii
        $mutex2 = "PNP#NETMUTEX#1#DL5" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // Generic: APC + memory write + thread/process enumeration.
            (
                3 of ($api_QueueUserAPC, $api_VirtualAllocEx, $api_WriteProcessMemory, $api_OpenProcess, $api_OpenThread) and
                3 of ($api_CreateToolhelp32Snapshot, $api_Thread32First, $api_Thread32Next, $api_Process32First, $api_Process32Next)
            )
            or
            // Targeted: APC + explorer + debug privilege.
            (
                $api_QueueUserAPC and $target_explorer and $priv_debug
            )
            or
            // Sample-specific: known mutex + APC.
            (
                any of ($mutex*) and $api_QueueUserAPC
            )
        )
}

rule linkinfo_DLL_injection_shellcode
{
    meta:
        description = "Detects the shellcode stub used by the file infector to drop and load the malicious linkinfo.dll."
        author = "gemesa@protonmail.com"
        hash = "f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad"
        mitre_attack = "T1055.004"
        reference = "DAT_100062a8 (shellcode stub appended to infected EXEs)"

    strings:
        // String embedded in shellcode stub.
        $shellcode_dllname = "\\linkinfo.dll" ascii

        // SEH chain walk. Find kernel32 base.
        /*
        $ echo "0x33,0xf6,0x64,0xad" | llvm-mc --disassemble -triple=i686-pc-windows-msvc --output-asm-variant=1
            xor	esi, esi
            lodsd	eax, dword ptr fs:[esi]
        */
        $seh_walk = { 33 F6 64 AD }

        // MZ header scan.
        /*
        $ echo "0x66,0x33,0xdb,0x66,0x81,0x3b,0x4d,0x5a" | llvm-mc --disassemble -triple=i686-pc-windows-msvc --output-asm-variant=1 --print-imm-hex
            xor	bx, bx
            cmp	word ptr [ebx], 0x5a4d
        */
        $mz_scan = { 66 33 DB 66 81 3B 4D 5A }

        // PE signature check.
        /*
        $ echo "0x81,0x3e,0x50,0x45,0x00,0x00" | llvm-mc --disassemble -triple=i686-pc-windows-msvc --output-asm-variant=1 --print-imm-hex
          cmp	dword ptr [esi], 0x4550
        */
        $pe_check = { 81 3E 50 45 00 00 }

        // Ordinal 101 call.
        /*
        $ echo "0x6a,0x65,0x50,0xff,0x13" | llvm-mc --disassemble -triple=i686-pc-windows-msvc --output-asm-variant=1 --print-imm-hex
            push	0x65
            push	eax
            call	dword ptr [ebx]
        */
        $ord101_call = { 6A 65 50 FF 13 }

        // Mutexes.
        $mutex1 = "PNP#DMUTEX#1#DL5" ascii
        $mutex2 = "PNP#NETMUTEX#1#DL5" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // Shellcode pattern: SEH walk + MZ scan + PE check + inline DLL name.
            ($seh_walk and $mz_scan and $pe_check and $shellcode_dllname)
            or
            // Shellcode with ordinal call.
            ($ord101_call and $shellcode_dllname)
            or
            // Infected binary with both shellcode string and mutex.
            ($shellcode_dllname and any of ($mutex*))
        )
}
