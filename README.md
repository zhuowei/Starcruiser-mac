Tool to connect to Meta Ray-Ban glasses over Bluetooth on macOS.

Right now it does nothing useful: it just prints the bytes of the single RequestEncryption message it receives over Bluetooth.

To use:

```
git submodule update --init
./protogen.sh
```

If this is the first time, put the glasses into pairing mode.

`swift run`

It should print:

```
central manager state update
[<CBPeripheral: 0x106704ed0, identifier = 41414141-4141-4141-4141-414141414141, name = Meta RB Display 0053, mtu = 0, state = disconnected>]
connected to peripheral <CBPeripheral: 0x106704ed0, identifier = 41414141-4141-4141-4141-414141414141, name = Meta RB Display 0053, mtu = 23, state = connected>
discover services: [<CBService: 0x1071041d0, isPrimary = YES, UUID = FD5F>]
discover characteristics
<CBCharacteristic: 0x107405140, UUID = 05ACBE9F-6F61-4CA9-80BF-C8BBB52991C0, properties = 0x12, value = {length = 1, bytes = 0x00}, notifying = NO>
<CBCharacteristic: 0x107405140, UUID = 05ACBE9F-6F61-4CA9-80BF-C8BBB52991C0, properties = 0x12, value = {length = 4, bytes = 0x00008100}, notifying = NO>
got characteristic... 4 bytes
l2cap channel: <CBL2CAPChannel: 0x1070045e0 peer = <CBPeripheral: 0x106704ed0, identifier = 41414141-4141-4141-4141-414141414141, name = Meta RB Display 0053, mtu = 517, state = connected>, psm = 129>
sent... 8
input stream: NSStreamEvent(rawValue: 1)
input stream: NSStreamEvent(rawValue: 2)
read 114
in packet: [removed]
2
input stream: NSStreamEvent(rawValue: 1)
input stream: NSStreamEvent(rawValue: 4)
```
