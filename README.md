# threat-detection-rules
Collection of YARA (`.yar`), Suricata (`.rules`) and Sigma (`.yml`) rules for detecting various malware threats. Sigma rules are only implemented for Linux or Windows hosts and are verified via `sigma check file.yml` but not tested otherwise. Additionally, Sigma rules are formatted via `prettier --write file.yml`.

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
$ unzip ChromeUpdater.apk -d chrome-updater-unzipped
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

# Xloader (MoqHao)

- [Analysis blog post](https://shadowshell.io/xloader)

- [Rules](xloader)

## Usage

### YARA

#### Loader

```
$ unzip xloader.apk -d xloader-unzipped
$ yara -s xloader-loader-android.yar -r xloader-unzipped
xloader_loader_android xloader-unzipped/AndroidManifest.xml
0x45a:$package: q\x00q\x00f\x00z\x00q\x00.\x00o\x00e\x00o\x00o\x00p\x00.\x00l\x00r\x00.\x00x\x00n\x00z\x00c\x00w\x00r\x00
0x752:$permission0: s\x00e\x00d\x00v\x00.\x00y\x00f\x00e\x00m\x00.\x00n\x00f\x00j\x00z\x00i\x00
0x774:$permission1: p\x00f\x00o\x00p\x00h\x00.\x00r\x00y\x00x\x00r\x00p\x00l\x00q\x00.\x00d\x00y\x00e\x00k\x00
0x79c:$permission2: r\x00z\x00c\x00a\x00d\x00.\x00q\x00k\x00w\x00o\x00o\x00o\x00z\x00.\x00u\x00a\x00l\x00x\x00q\x00
0x7c6:$permission3: b\x00c\x00e\x00m\x00r\x00.\x00f\x00j\x00s\x00h\x00n\x00c\x00i\x00.\x00x\x00f\x00a\x00n\x00v\x00
0x7f0:$permission4: q\x00r\x00z\x00s\x00z\x00n\x00k\x00o\x00.\x00g\x00s\x00g\x00e\x00y\x00z\x00.\x00f\x00z\x00t\x00i\x00y\x00
0x81e:$permission5: p\x00p\x00h\x00n\x00x\x00s\x00h\x00u\x00.\x00b\x00h\x00x\x00e\x00.\x00r\x00x\x00g\x00k\x00l\x00x\x00n\x00y\x00
0xb30:$pc0: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00G\x00N\x00u\x00A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00
0xb74:$pc1: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00C\x00r\x00A\x00c\x00t\x00i\x00v\x00i\x00t\x00y\x00
0xc9a:$pc2: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00U\x00x\x00
0xcc6:$pc3: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00R\x00y\x00
0xd76:$pc4: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00J\x00z\x00
0xe22:$pc5: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00L\x00i\x00
0xf30:$pc6: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00A\x00p\x00
0x105c:$pc7: g\x00f\x006\x00h\x008\x00y\x008\x00.\x00Y\x00i\x00
```

#### Payload

```
$ yara -s xloader-payload-android.yar payload.dex
xloader_payload_android payload.dex
0x6d5b6:$rpc0: sendSms
0x68601:$rpc1: setWifi
0x6d9ce:$rpc1: setWifi
0x6d9d7:$rpc1: setWifi
0x6d9e7:$rpc1: setWifi
0x6a11e:$rpc2: gcont
0x4c906:$rpc3: lock
0x4d11a:$rpc3: lock
0x4df9f:$rpc3: lock
0x4e3ea:$rpc3: lock
0x4e6b4:$rpc3: lock
0x4ea70:$rpc3: lock
0x4ed7a:$rpc3: lock
0x4f1c9:$rpc3: lock
0x4f49a:$rpc3: lock
0x4f868:$rpc3: lock
0x4fb76:$rpc3: lock
0x4ffd4:$rpc3: lock
0x502a4:$rpc3: lock
0x50688:$rpc3: lock
0x50997:$rpc3: lock
0x50d26:$rpc3: lock
0x50ff1:$rpc3: lock
0x513d4:$rpc3: lock
0x51cb1:$rpc3: lock
0x51e6d:$rpc3: lock
0x521fc:$rpc3: lock
0x524c3:$rpc3: lock
0x528a5:$rpc3: lock
0x52943:$rpc3: lock
0x54e87:$rpc3: lock
0x55485:$rpc3: lock
0x56197:$rpc3: lock
0x561d7:$rpc3: lock
0x56653:$rpc3: lock
0x5666f:$rpc3: lock
0x5667b:$rpc3: lock
0x5668c:$rpc3: lock
0x566bf:$rpc3: lock
0x56fa0:$rpc3: lock
0x57027:$rpc3: lock
0x57031:$rpc3: lock
0x57185:$rpc3: lock
0x57190:$rpc3: lock
0x5719a:$rpc3: lock
0x571ab:$rpc3: lock
0x571d9:$rpc3: lock
0x5812e:$rpc3: lock
0x58154:$rpc3: lock
0x58174:$rpc3: lock
0x581cb:$rpc3: lock
0x581de:$rpc3: lock
0x58289:$rpc3: lock
0x582ab:$rpc3: lock
0x58312:$rpc3: lock
0x58d17:$rpc3: lock
0x59079:$rpc3: lock
0x590f2:$rpc3: lock
0x5911a:$rpc3: lock
0x5a15c:$rpc3: lock
0x5a167:$rpc3: lock
0x5a177:$rpc3: lock
0x5a188:$rpc3: lock
0x5a3b9:$rpc3: lock
0x5a698:$rpc3: lock
0x5aaa1:$rpc3: lock
0x5b4eb:$rpc3: lock
0x5b56b:$rpc3: lock
0x5d11d:$rpc3: lock
0x5d381:$rpc3: lock
0x5d696:$rpc3: lock
0x5dee9:$rpc3: lock
0x5e1c9:$rpc3: lock
0x5e32e:$rpc3: lock
0x5e504:$rpc3: lock
0x5e64f:$rpc3: lock
0x64855:$rpc3: lock
0x64883:$rpc3: lock
0x684c3:$rpc3: lock
0x6b6c1:$rpc3: lock
0x6be44:$rpc3: lock
0x6be4a:$rpc3: lock
0x6d52c:$rpc3: lock
0x2cf7b:$rpc4: bc
0x682cf:$rpc4: bc
0x68c53:$rpc4: bc
0x6b904:$rpc4: bc
0x6e00e:$rpc4: bc
0x6e125:$rpc4: bc
0x6e171:$rpc4: bc
0x6e1f4:$rpc4: bc
0x6d78e:$rpc5: setForward
0x6a43b:$rpc6: getForward
0x6ab10:$rpc7: hasPkg
0x6d928:$rpc8: setRingerMode
0x685b1:$rpc9: setRecEnable
0x6d8ce:$rpc9: setRecEnable
0x6d2d4:$rpc10: reqState
0x6da11:$rpc11: showHome
0x6da1b:$rpc11: showHome
0x6aa2b:$rpc12: getnpki
0x4dae2:$rpc13: http
0x4dbea:$rpc13: http
0x530cc:$rpc13: http
0x5aed0:$rpc13: http
0x66770:$rpc13: http
0x6ab8b:$rpc13: http
0x6ab91:$rpc13: http
0x6abb7:$rpc13: http
0x6abc0:$rpc13: http
0x6abd3:$rpc13: http
0x6abda:$rpc13: http
0x6abeb:$rpc13: http
0x6abf5:$rpc13: http
0x6ac13:$rpc13: http
0x6ac3f:$rpc13: http
0x6ac72:$rpc13: http
0x6ac93:$rpc13: http
0x6acb1:$rpc13: http
0x6acd9:$rpc13: http
0x6acfd:$rpc13: http
0x6ad1c:$rpc13: http
0x6ad44:$rpc13: http
0x6ad6e:$rpc13: http
0x6ad9b:$rpc13: http
0x6adca:$rpc13: http
0x6adf0:$rpc13: http
0x6ae18:$rpc13: http
0x6ae41:$rpc13: http
0x6ae70:$rpc13: http
0x6ae9a:$rpc13: http
0x6aec7:$rpc13: http
0x6b4ca:$rpc13: http
0x6db2d:$rpc13: http
0x6ccc9:$rpc14: onRecordAction
0x5147b:$rpc15: call
0x529ed:$rpc15: call
0x531f6:$rpc15: call
0x53cc3:$rpc15: call
0x540e2:$rpc15: call
0x540f9:$rpc15: call
0x5411c:$rpc15: call
0x54134:$rpc15: call
0x54157:$rpc15: call
0x542ed:$rpc15: call
0x544e4:$rpc15: call
0x5479b:$rpc15: call
0x54a94:$rpc15: call
0x54a9d:$rpc15: call
0x54b05:$rpc15: call
0x54b0e:$rpc15: call
0x54b35:$rpc15: call
0x54b3e:$rpc15: call
0x55f16:$rpc15: call
0x57236:$rpc15: call
0x573b8:$rpc15: call
0x57419:$rpc15: call
0x57433:$rpc15: call
0x57486:$rpc15: call
0x57a6e:$rpc15: call
0x5a275:$rpc15: call
0x5ac54:$rpc15: call
0x5adbe:$rpc15: call
0x66550:$rpc15: call
0x66566:$rpc15: call
0x68d4e:$rpc15: call
0x68d54:$rpc15: call
0x68d5b:$rpc15: call
0x68d65:$rpc15: call
0x6b450:$rpc15: call
0x6cbc4:$rpc15: call
0x6cc57:$rpc15: call
0x6cd31:$rpc15: call
0x6cdb5:$rpc15: call
0x6a9fe:$rpc16: get_apps
0x5f91d:$rpc17: ping
0x6cf7b:$rpc17: ping
0x6cf81:$rpc17: ping
0x6a744:$rpc18: getPhoneState
0x6aa08:$rpc19: get_gallery
0x6aa15:$rpc20: get_photo
0x6cdb2:$rpc21: on_call_rec
0x6b44d:$rpc22: is_call_rec_enable
0x6d847:$rpc23: setMyInfo
0x6d852:$rpc24: setMyVCode
0x6cde7:$rpc25: openbrowser2
0x6ad6e:$pinterest0: https://www.pinterest.com/emeraldquinn4090/
0x6ae41:$pinterest1: https://www.pinterest.com/kelliemarshall9518/
0x6ae9a:$pinterest2: https://www.pinterest.com/shonabutler10541/
0x6ae70:$pinterest3: https://www.pinterest.com/norahspencer9/
0x6aec7:$pinterest4: https://www.pinterest.com/singletonabigail/
0x6ad9b:$pinterest5: https://www.pinterest.com/felicitynewman8858/
0x6ad1c:$pinterest6: https://www.pinterest.com/abigailn674/
0x6adca:$pinterest7: https://www.pinterest.com/gh6855786/
0x6ad44:$pinterest8: https://www.pinterest.com/catogreggex11/
0x6ae18:$pinterest9: https://www.pinterest.com/ingalcliffth/
0x6adf0:$pinterest10: https://www.pinterest.com/husaincrisp/
0x69fbd:$vk0: ffgtrrt([\w_-]+?)ffgtrrt
0x6a08e:$vk1: freefh([\w_-]+?)freefh
0x6aa64:$vk2: gfrtthnm([\w_-]+?)gfrtthnm
0x6cb12:$vk3: ohgftyn([\w_-]+?)ohgftyn
0x69fa5:$vk4: fdthjn([\w_-]+?)fdthjn
0x6aa80:$vk5: gftrtr([\w_-]+?)gftrtr
0x68c5b:$vk6: bgfrewi([\w_-]+?)bgfrewi
0x6aef4:$vk7: htynff([\w_-]+?)htynff
0x6ab42:$vk8: hfdrgf([\w_-]+?)hfdrgf
0x69f6a:$vk9: fdedsds([\w_-]+?)fdedsds
0x69df1:$vk10: dsfewdw([\w_-]+?)dsfewdw
0x6d35e:$vk11: retredwcd([\w_-]+?)retredwcd
0x5cc7a:$fs0: /NPKI
0x5cc1d:$fs1: .rec
0x5cc23:$fs1: .rec
0x5cc23:$fs2: .rec.amr
0x6b8fc:$bank0: jp.co.smbc.direct
0x6b8bf:$bank1: jp.co.rakuten_bank.rakutenbank
0x6b92d:$bank2: jp.mufg.bk.applisp.app
0x6b85e:$bank3: jp.co.japannetbank.smtapp.balance
0x6b89c:$bank4: jp.co.netbk.smartkey.SSNBSmartkey
0x6b90f:$bank5: jp.japanpost.jp_bank.FIDOapp
0x6b881:$bank6: jp.co.jibunbank.jibunmain
0x6b8df:$bank7: jp.co.sevenbank.AppPassbook
0x5e1cf:$field0: \xEA\xB3\xB5\xEC\x9D\xB8\xEC\x9D\xB8\xEC\xA6\x9D\xEC\x84\x9C
0x5d387:$field1: \xEB\xB9\x84\xEB\xB0\x80\xEB\xB2\x88\xED\x98\xB8
0x5daad:$field1: \xEB\xB9\x84\xEB\xB0\x80\xEB\xB2\x88\xED\x98\xB8
0x5d7b1:$field2: \xEC\xB9\xB4\xEB\x93\x9C\xEB\xB2\x88\xED\x98\xB8
0x5d882:$field3: \xEC\xB9\xB4\xEB\x93\x9C\xEC\x86\x8C\xEC\x9C\xA0\xEC\x9E\x90\xEB\xAA\x85
0x5d96d:$field4: \xEC\x9C\xA0\xED\x9A\xA8\xEA\xB8\xB0\xEA\xB0\x84
0x5dd90:$field5: \xEC\x9A\xB0\xED\x8E\xB8\xEB\xB2\x88\xED\x98\xB8
```

# DCRat

- [Analysis blog post](https://shadowshell.io/dcrat)

- [Rules](dcrat)

## Usage

### YARA

```
$ yara dcrat.yar dcrat.exe 
DCRat_salt dcrat.exe
DCRat_AntiProcess dcrat.exe
DCRat_AMSI_bypass dcrat.exe
DCRat_VM_detection dcrat.exe
DCRat_config dcrat.exe
DCRat_MsgPack_packets dcrat.exe
DCRat_persistence dcrat.exe
```
