# gminfo-3.7-3.8-ADB-EEPROM
EEPROM Modification to Enable ADB Access, Disables Authorized Secure ADB Client requirment.

Using a dump tool/software, extract the firmware from the indentified IC. Using any Hex editor, flip the following. Then write back to IC, tripple check your work.

For example using minipro on macOS with an XGecu Programmer
minipro -p "M24C64" -r dump.bin
minipro -p "M24C64" -w modified.bin
minipro -p "M24C64" -r verify.bin

===============================================

  - Byte 0x440: 0x5A (framing byte)
  - Byte 0x441: 0x00 ← Security flag = ENABLED
  - Byte 0x442: 0x5A (framing byte)

  - Byte 0xa80: 0x5A (framing byte)
  - Byte 0xa81: 0x00 ← Security flag = ENABLED
  - Byte 0xa82: 0x5A (framing byte)

===============================================

  - Byte 0x440: 0x5A (framing byte)
  - Byte 0x441: 0xFF ← Security flag = DISABLED
  - Byte 0x442: 0x5A (framing byte)

  - Byte 0xa80: 0x5A (framing byte)
  - Byte 0xa81: 0xFF ← Security flag = DISABLED
  - Byte 0xa82: 0x5A (framing byte)

IC in question is an ST M24C64 TSSOP8, using a Tool like XGecu Programmer. The framing byte appears to change depending on Firmware Version (Android OTA). Each update will reset back to 0x00 and lock ADB access.

Last Known modifiable Build was Y181 for RPO: IOK identified radios.
I have had issues with HexEdit on macOS not saving changes to the file. So double check any modifications to the file have been saved properly before writing back to IC.
