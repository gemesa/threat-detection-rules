# threat-detection-rules
Collection of YARA and Suricata rules for detecting various malware threats

# Qilin

- [Analysis blog post](https://shadowshell.io/qilin-ransomware)

- [Rules](qilin)

## Usage

### YARA

```
$ yara -s qilin.yar qilin-esxi.elf
qilin qilin-esxi.elf
0xe92b6:$1: Disables process kill
0xe92e6:$2: Disables rename of completed files
0xe9323:$3: Disables snapshot deletion
0xe9358:$4: Disables VM kill
0xebc00:$5: for I in $(esxcli storage filesystem list |grep 'VMFS-5' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done
0xebcc0:$6: for I in $(esxcli storage filesystem list |grep 'VMFS-5' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk; vmkfstools -U $I/eztDisk; done
0xebd68:$7: for I in $(esxcli storage filesystem list |grep 'VMFS-6' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done
0xebe28:$8: for I in $(esxcli storage filesystem list |grep 'VMFS-6' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk; vmkfstools -U $I/eztDisk; done
0xebed0:$9: esxcfg-advcfg -s 32768 /BufferCache/MaxCapacity
0xebf00:$10: esxcfg-advcfg -s 20000 /BufferCache/FlushInterval
0xec032:$11: esxcli vm process list
0xebbd8:$12: esxcli vm process kill -t force -w %llu
0xec05b:$13: vim-cmd vmsvc/getallvms
0xebfc0:$14: vim-cmd vmsvc/snapshot.removeall %llu > /dev/null 2>&1
0xe9ce9:$15: dhl:p:Rrt:wy
0xe9cda:$16: %s_RECOVER.txt
0xe9ea9:$17: /etc/motd.template
0xe9ebc:$18: /var/run/motd
0xe954c:$19: /etc/motd
0xe9ea9:$19: /etc/motd
0xe9eca:$19: /etc/motd
0xeb3a8:$20: -----BEGIN PUBLIC KEY-----
0xeb3a8:$21: -----BEGIN PUBLIC KEY-----\x0AMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3a4G68kgJX2bwWZX23Yz\x0AzPI68Fl6eocJ+XLcPN9dvG3o/SV04F2zE7nWUhBbwsBHiX8bIquqVyVV+Y93FOCn\x0AeJODySiy+bLZ1QfXKMjoNbhHq+aeuYCV8na3LF3hoGpST6uJpXUxbhZOBqHHbbx6\x0AvVy1fXOUEvaEOhqkglfDUQ7/fH6sT1p/3RyCtGi3o7588oMHOVgz3jZux2dqp9Zy\x0APs9MqZs0OtcBAXTG4EmD8yz2RgH+D9j756snWNZeknnjNO+KUARDSICKFOYtb3wz\x0AxYFVvACB3sJuTpAJ2HuaWIEo8NljGsMkNTqy3tFY0WnUBxAgt7AMUM+Ex75DGa9H\x0AIAXd+bTOfo+zyUGKiUFBqBZjo8T0ueTpr8BZb98fl5/LFpXmBuR/dJBfeuq3a4vK\x0AFpxx796zUe/hoiBSvw9GzLyYa5A5Lb
0xebb0b:$22: Detected OS: ESXi (%d)
0xe9c10:$23: Are you sure to start encryption? (y/n)
0xe9c88:$24: File tree traversing done. Waiting workers to complete...
0xe9703:$25: Qilin
0xe970d:$26: Your network/system was encrypted.
0xe9b86:$27: o7L03e8F9J
0xeb099:$27: o7L03e8F9J
```

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

# Mirai SORA ARM

- [Analysis blog post](https://shadowshell.io/mirai-sora-botnet)
- [Rules](mirai-sora-arm)

## Usage

### YARA

```
$ yara -s mirai-packed.yar mirai-packed.elf
mirai_sora_packed_arm mirai-packed.elf
0x98:$1: UPX!
0x6deb:$1: UPX!
0x6df4:$1: UPX!
0x6670:$2: $Info: This file is packed with the UPX executable packer http://upx.sf.net $
0x66bf:$3: $Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $
0x1b1:$4: y$Qdl%
0x2e2:$5: aym&,ZYeC
0x35a:$6: :b[;tgo
0x440:$7: 1`Rg{z
0x484:$8: R5&9Sc
0x6f6:$9: \ME'Tj
0x749:$10: RSB$<|R
0x855:$11: a> ~!wqgUY
0x88e:$12: fZ{Glb
0xa8c:$13: ld@j^]~
0xca0:$14: 902n\x09SP
0xde2:$15: gP';H;
0x1151:$16: ~-%&xI
0x13ab:$17: 0N?>BH
0x14d7:$18: 8?oVM\3
```

```
$ yara -s mirai-unpacked.yar mirai-unpacked.elf
mirai_sora_unpacked_arm mirai-unpacked.elf
0xfb94:$1: 154.7.253.207
0x10b80:$2: AF FB DE DE
0xfd28:$3: 07 1B 06 15 6E 74 35 24 24 38 31 20 74 3A 3B 20 74 32 3B 21 3A 30 54 00
0xfd14:$4: 7B 36 3D 3A 7B 36 21 27 2D 36 3B 2C 74 07 1B 06 15 54 00 00
0x107f0:$5: 17 3B 3A 3A 31 37 20 31 30 74 00 3B 74 17 1A 17 54 00 00 00
0xfe08:$6: 7B 30 31 22 7B 23 35 20 37 3C 30 3B 33 54 00
0xfe18:$7: 7B 30 31 22 7B 39 3D 27 37 7B 23 35 20 37 3C 30 3B 33 54 00
0xfcf0:$8: 51 74 00 00
0xfe38:$9: 3B 33 3D 3A 54 00
0xfe40:$10: 31 3A 20 31 26 54 00
0xfd00:$11: 31 3A 35 36 38 31 54 00
0xfd08:$12: 27 2D 27 20 31 39 54 00
0xfd10:$13: 27 3C 54 00
0xfcf8:$14: 27 3C 31 38 38 54 00
0xfd40:$15: 3A 37 3B 26 26 31 37 20 54 00
0xfd78:$16: 7B 24 26 3B 37 7B 54 00
0xfd80:$17: 7B 31 2C 31 54 00
0xfdbc:$18: 7A 35 3A 3D 39 31 54 00
0x7f98:$19: 00 20 A0 E3 06 30 D2 E7 54 30 23 E2 06 30 C2 E7 01 20 82 E2 02 00 57 E1 F9 FF FF 1A
0xb1b0:$20: 00 C0 A0 E3 00 20 9E E5 02 30 DC E7 03 30 20 E0 02 30 CC E7 00 10 9E E5 01 30 DC E7 03 30 26 E0 01 30 CC E7 00 20 9E E5 02 30 DC E7 03 30 25 E0 02 30 CC E7 00 10 9E E5 01 30 DC E7 03 30 24 E0 ...
0xb268:$20: 00 C0 A0 E3 00 20 9E E5 02 30 DC E7 03 30 20 E0 02 30 CC E7 00 10 9E E5 01 30 DC E7 03 30 26 E0 01 30 CC E7 00 20 9E E5 02 30 DC E7 03 30 25 E0 02 30 CC E7 00 10 9E E5 01 30 DC E7 03 30 24 E0 ...
```

### Suricata

```
$ sudo suricata -c /etc/suricata/suricata.yaml -s mirai.rules -i 
$ sudo tail -f /var/log/suricata/fast.log
04/04/2025-16:15:20.435158  [**] [1:1000003:1] Mirai SORA C2 [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.128:49250 -> 154.7.253.207:1312
```

# Fake Chrome updater

- [Analysis blog post](https://shadowshell.io/fake-chrome-updater)

- [Rules](fake-chrome-updater)

## Usage

### YARA

```
$ mkdir chrome-updater-unzipped
$ cp ChromeUpdater.apk chrome-updater-unzipped/
$ cd chrome-updater-unzipped
$ unzip ChromeUpdater.apk
$ rm ChromeUpdater.apk
$ cd ..
$ yara -s fake_chrome_updater_xml_android.yar fake_chrome_updater_dex_android.yar -r chrome-updater-unzipped
fake_chrome_updater_xml_android chrome-updater-unzipped/res/layout/main.xml
0xff:$0: Google Chrome Updater
0x131:$1: Your Chrome version is outdated! Chrome version: 65.1 (19 years ago!)
0xe1:$2: Download and install update
fake_chrome_updater_dex_android chrome-updater-unzipped/classes54.dex
0x71cad:$0: ATwvXhg0JDYNWzQ6YVkYJyEoDVc7dD9CTSd0IkhOPDcjAw==
0x7e2aa:$1: Gh8=
0x83e09:$2: OTshTlkhdGtO
0x83dff:$3: OTshTlkh
0x83e09:$3: OTshTlkh
0x7e248:$4: GTshSl0ndCFCTHU/L0FUMDBoDWowJzJMSiE9KEoW
0x7e294:$5: GTshSl0ndDVZVyUkI0kW
```
