# threat-detection-rules
Collection of YARA and Suricata rules for detecting various malware threats

# Hancitor

- [Analysis blog post](https://shadowshell.io/hancitor-loader)

- [Rules](hancitor)

## Usage

### YARA

```
$ yara -s hancitor-packed.yar hancitor.dll
hancitor_packed hancitor.dll
0x5d3e6:$1: Broke
0x5d3ec:$2: Necessaryearly
0x5ac6b:$_memcpy: 68 88 0E 00 00 68 10 75 00 10 68 18 09 06 10 E8
0x5b526:$GetSystemDirectoryW: 68 83 05 00 00 8D 54 24 34 52 FF 15
0x5a3ad:$GetModuleFileNameW: 68 83 05 00 00 68 20 FC 05 10 6A 00 FF 15
0x5a401:$VirtualProtectEx: A1 20 20 07 10 8B 15 94 F0 05 10 68 14 09 06 10 6A 40 68 00 51 00 00 50 6A FF 8D 9C 16 0F 01 00 00 FF 15
0x5a4f9:$GetCurrentDirectoryW: 2A C2 68 20 FC 05 10 02 C3 68 83 05 00 00 A2 68 F0 05 10 FF 15
0x28e6f:$decrypt1: 8A DA 2A D8 02 D9 80 C3 19 0F B6 CB 2B CA 0F B7 D6 03 D1 89 15
0x28e88:$decrypt2: 8B 1D B8 F0 05 10 81 C7 D0 64 08 01 8A CB 2A C8 89 7D 00 80 C1 17 83 C5 04 83 6C 24 10 01 89 3D
```

```
$ yara -s hancitor-unpacked.yar hancitor-unpacked.dll
hancitor_unpacked hancitor-unpacked.dll
0x3168:$1: Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
0x31d0:$2: http://api.ipify.org
0x31e8:$3: 0.0.0.0
0x31f0:$4: ncdrleb
0x31f8:$5: GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)
0x3238:$6: GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)
0x32c4:$7: Rundll32.exe %s, start
0x32fa:$8: svchost.exe
0x32a8:$9: explorer.exe
0x32e4:$10: SystemRoot
0x32f0:$11: \System32\svchost.exe
0x33ec:$12: MASSLoader.dll
0x33fb:$13: FCQNEAXPXCR
0x3407:$14: GSDEAEBPVHTSM
0x211c:$CryptCreateHash: 8D 4D FC 51 6A 00 6A 00 68 04 80 00 00 8B 55 F8 52 FF 15
0x2157:$CryptDeriveKey: 8D 45 F4 50 8B 4D EC 51 8B 55 FC 52 68 01 68 00 00 8B 45 F8 50 FF 15
```

### Suricata

```
$ sudo suricata -c /etc/suricata/suricata.yaml -s hancitor.rules -i enp0s3
$ sudo tail -f /var/log/suricata/fast.log
02/24/2025-15:31:54.255497  [**] [1:1000001:2] Hancitor beacon [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.129:49929 -> 192.168.56.128:80
02/24/2025-15:31:54.275576  [**] [1:1000001:2] Hancitor beacon [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.129:49930 -> 192.168.56.128:80
02/24/2025-15:31:54.299836  [**] [1:1000001:2] Hancitor beacon [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.129:49931 -> 192.168.56.128:80
```
