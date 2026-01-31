/*
  meta:
    description = "DCRat"
    author = "Andras Gemes"
    date = "2026-02-01"
    sha256 = "cfe65a88ebc858c083c6bfd48d1caf16128a420d9352b46c3107b8b1a1614639"
    ref1 = "https://shadowshell.io/dcrat"
    ref2 = "https://bazaar.abuse.ch/sample/cfe65a88ebc858c083c6bfd48d1caf16128a420d9352b46c3107b8b1a1614639"
    ref3 = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat"
    ref4 = "https://github.com/qwqdanchun/DcRat"
*/

rule DCRat_salt
{
    meta:
        description = "Detects DCRat by hardcoded salt in Aes256 class."
        reference = "Aes256.cs"
        
    strings:
        $salt = "DcRatByqwqdanchun" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and $salt
}

rule DCRat_AntiProcess
{
    meta:
        description = "Detects DCRat anti-analysis process kill list."
        reference = "AntiProcess.cs"
        
    strings:
        $p1 = "Taskmgr.exe" ascii wide
        $p2 = "ProcessHacker.exe" ascii wide
        $p3 = "procexp.exe" ascii wide
        $p4 = "MSASCui.exe" ascii wide
        $p5 = "MsMpEng.exe" ascii wide
        $p6 = "MpUXSrv.exe" ascii wide
        $p7 = "MpCmdRun.exe" ascii wide
        $p8 = "NisSrv.exe" ascii wide
        $p9 = "ConfigSecurityPolicy.exe" ascii wide
        $p10 = "MSConfig.exe" ascii wide
        $p11 = "Regedit.exe" ascii wide
        $p12 = "UserAccountControlSettings.exe" ascii wide
        $p13 = "taskkill.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and 6 of ($p*)
}

rule DCRat_AMSI_bypass
{
    meta:
        description = "Detects base64 encoded AMSI bypass strings."
        reference = "Amsi.cs"
        
    strings:
        // "amsi.dll" base64
        $amsi_dll = "YW1zaS5kbGw=" ascii wide
        // "AmsiScanBuffer" base64
        $amsi_func = "QW1zaVNjYW5CdWZmZXI=" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule DCRat_AMSI_patch
{
    meta:
        description = "Detects AMSI patch shellcode bytes."
        reference = "Amsi.cs"
        
    strings:
        /*
        $ echo "uFcAB4DD" | base64 -d | xxd -p | sed 's/../0x& /g' | llvm-mc --disassemble --triple=x86_64
	    movl	$2147942487, %eax               # imm = 0x80070057
	    retq
        $ echo "uFcAB4DCGAA=" | base64 -d | xxd -p | sed 's/../0x& /g' | llvm-mc --disassemble --triple=i386 
	    movl	$2147942487, %eax               # imm = 0x80070057
	    retl	$24
        */
        $patch_x64 = { B8 57 00 07 80 C3 }
        $patch_x86 = { B8 57 00 07 80 C2 18 00 }
        $patch_b64_x64 = "uFcAB4DD" ascii wide
        $patch_b64_x86 = "uFcAB4DCGAA=" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule DCRat_VM_detection
{
    meta:
        description = "Detects DCRat VM detection via WMI."
        reference = "Anti_Analysis.cs"
        
    strings:
        $wmi1 = "Win32_CacheMemory" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule DCRat_config
{
    meta:
        description = "Detects DCRat configuration field names."
        reference = "Settings.cs"
        
    strings:
        $f1 = "Por_ts" ascii wide
        $f2 = "Hos_ts" ascii wide
        $f3 = "Key" ascii wide
        $f4 = "Paste_bin" ascii wide
        $f5 = "BS_OD" ascii wide
        $f6 = "Hw_id" ascii wide
        $f7 = "Anti_Process" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 5 of them
}

rule DCRat_MsgPack_packets
{
    meta:
        description = "Detects DCRat C2 packet identifiers."
        reference = "ClientSocket.cs"
        
    strings:
        $pkt1 = "Pac_ket" ascii wide
        $pkt2 = "ClientInfo" ascii wide
        $pkt3 = "plu_gin" ascii wide
        $pkt4 = "save_Plugin" ascii wide
        $pkt5 = "Po_ng" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule DCRat_persistence
{
    meta:
        description = "Detects DCRat persistence mechanism strings."
        reference = "NormalStartup.cs"
        
    strings:
        // Base64: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
        $user = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" ascii wide
        // Base64: "/c schtasks /create /f /sc onlogon /rl highest /tn "
        $admin = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule DCRat_Combined
{
    meta:
        description = "Combined DCRat detection rule."
        
    condition:
        DCRat_salt and DCRat_AntiProcess and
        DCRat_AMSI_bypass and DCRat_AMSI_patch and
        DCRat_VM_detection and DCRat_config and
        DCRat_MsgPack_packets and DCRat_persistence
}
