/*
  meta:
    description = "Remcos RAT"
    author = "Andras Gemes"
    date = "2026-02-08"
    sha256 = "94a4e5c7a3524175c0306c5748c719a940a7bfbe778c5a16627193a684fa10f0"
    ref1 = "https://shadowshell.io/remcos"
    ref2 = "https://bazaar.abuse.ch/sample/94a4e5c7a3524175c0306c5748c719a940a7bfbe778c5a16627193a684fa10f0"
    ref3 = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos"
*/

rule Remcos_version_agent_breakingsecurity_strings
{
    meta:
        description = "Detects Remcos RAT version, agent and BreakingSecurity strings."
        
    strings:
        $v1 = "Remcos v" ascii wide
        $v2 = /\d+\.\d+\.\d+ Pro/ ascii wide
        $v3 = "Remcos Agent" ascii wide
        $v4 = "BreakingSecurity.net" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Remcos_keylogger_strings
{
    meta:
        description = "Detects Remcos keylogger strings."
        
    strings:
        $k1 = "Offline Keylogger Started" ascii wide
        $k2 = "Online Keylogger Started" ascii wide
        $k3 = "Keylogger initialization failure" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Remcos_uac_disable
{
    meta:
        description = "Detects Remcos UAC disable technique."
        
    strings:
        $reg1 = "Policies\\System" ascii wide
        $reg2 = "EnableLUA" ascii wide
        $cmd = "reg.exe ADD" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Remcos_audio_recording
{
    meta:
        description = "Detects Remcos audio recording capability."
        
    strings:
        $api1 = "waveInOpen" ascii
        $api2 = "waveInStart" ascii
        
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Remcos_c2_strings
{
    meta:
        description = "Detects Remcos C2 connection strings."
        
    strings:
        $s1 = "Connection Error: Unable to create socket" ascii wide
        $s2 = "Connected   | " ascii wide
        $s3 = "TLS On" ascii wide
        $s4 = "TLS Off" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Remcos_combined
{
    meta:
        description = "Combined Remcos RAT detection rule."
        
    condition:
        Remcos_version_agent_breakingsecurity_strings and
        Remcos_keylogger_strings and
        Remcos_uac_disable and
        Remcos_audio_recording and
        Remcos_c2_strings
}