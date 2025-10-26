import CoreBluetooth
import Foundation

let metaPsmServiceUuid = CBUUID(string: "fd5f")
let metaPsmCharacteristicUuid = CBUUID(string: "05ACBE9F-6F61-4CA9-80BF-C8BBB52991C0")

var myDeviceUuid: UUID! = nil
do {
  let uuidString =
    try NSString(contentsOfFile: "device_uuid.txt", encoding: NSUTF8StringEncoding) as String
  myDeviceUuid = UUID(uuidString: uuidString)
} catch {}

// 4 byte payload: 0x3 = error, error = 0xc001 (service_not_found)
let hardcodedPacket: [UInt8] = [0x80, 0x04, 0x00, 0x01, 0x03, 0x00, 0xc0, 0x01]

class Starcruiser: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, StreamDelegate {
  private let cbCentral = CBCentralManager()
  private var myPeripheral: CBPeripheral!
  private var l2cap: CBL2CAPChannel!
  override init() {
    super.init()
    cbCentral.delegate = self
  }
  func centralManagerDidUpdateState(_ central: CBCentralManager) {
    print("central manager state update")
    // cbCentral.scanForPeripherals(withServices: [metaPsmServiceUuid])
    if myDeviceUuid == nil {
      cbCentral.scanForPeripherals(withServices: [metaPsmServiceUuid])
    } else {
      let devices = cbCentral.retrievePeripherals(withIdentifiers: [myDeviceUuid])
      print(devices)
      myPeripheral = devices[0]
      myPeripheral.delegate = self
      cbCentral.connect(myPeripheral)
    }
  }
  func centralManager(
    _ central: CBCentralManager,
    didDiscover peripheral: CBPeripheral,
    advertisementData: [String: Any],
    rssi RSSI: NSNumber
  ) {
    print(peripheral)
    cbCentral.stopScan()
    myPeripheral = peripheral
    myPeripheral.delegate = self
    try! (myPeripheral.identifier.uuidString as NSString).write(
      toFile: "device_uuid.txt", atomically: true, encoding: NSUTF8StringEncoding)
    cbCentral.connect(peripheral)
  }

  func centralManager(
    _ central: CBCentralManager,
    didConnect peripheral: CBPeripheral
  ) {
    print("connected to peripheral \(peripheral)")
    myPeripheral.discoverServices([metaPsmServiceUuid])
  }

  func centralManager(
    _ central: CBCentralManager,
    didFailToConnect peripheral: CBPeripheral,
    error: (any Error)?
  ) {
    print("failed to connect: \(error!)")
  }

  func peripheral(
    _ peripheral: CBPeripheral,
    didDiscoverServices error: (any Error)?
  ) {
    print("discover services: \(peripheral.services!)")
    myPeripheral.discoverCharacteristics(
      [metaPsmCharacteristicUuid], for: myPeripheral.services![0])
  }

  func peripheral(
    _ peripheral: CBPeripheral,
    didDiscoverCharacteristicsFor service: CBService,
    error: (any Error)?
  ) {
    print("discover characteristics")
    let myCharacteristic = myPeripheral.services![0].characteristics![0]
    print("\(myCharacteristic)")
    //myPeripheral.setNotifyValue(true, for: myCharacteristic)
    myPeripheral.readValue(for: myCharacteristic)
  }

  func peripheral(
    _ peripheral: CBPeripheral,
    didUpdateValueFor characteristic: CBCharacteristic,
    error: (any Error)?
  ) {
    let myCharacteristic = myPeripheral.services![0].characteristics![0]
    print(myCharacteristic)
    guard let value = myCharacteristic.value else {
      print("no value?")
      myPeripheral.readValue(for: myCharacteristic)
      return
    }
    print("got characteristic... \(value)")
    if value.count != 4 {
      return
    }
    let psm = UInt(value[2]) | (UInt(value[3]) << 8)
    myPeripheral.openL2CAPChannel(CBL2CAPPSM(psm))
  }

  func peripheral(
    _ peripheral: CBPeripheral,
    didOpen channel: CBL2CAPChannel?,
    error: (any Error)?
  ) {
    guard let channel = channel else {
      print("l2cap channel fail: \(error!)")
      return
    }
    print("l2cap channel: \(channel)")
    l2cap = channel
    channel.inputStream.delegate = self
    channel.inputStream.schedule(in: RunLoop.main, forMode: .default)
    channel.outputStream.delegate = self
    channel.outputStream.schedule(in: RunLoop.main, forMode: .default)
    channel.inputStream.open()
    channel.outputStream.open()
    // let's send some stuff on the l2cap link.
    // we should be writing a RequestEncryption message here, but for now send an error...
    let wroteLength = channel.outputStream.write(hardcodedPacket, maxLength: hardcodedPacket.count)
    print("sent... \(wroteLength)")

  }

  func stream(
    _ aStream: Stream,
    handle eventCode: Stream.Event
  ) {
    print("input stream: \(eventCode)")
    if aStream == l2cap.inputStream && eventCode == Stream.Event.hasBytesAvailable {
      var inputBuffer = [UInt8](repeating: 0, count: 0x1000)
      let readSize = inputBuffer.withUnsafeMutableBytes { buf in
        l2cap.inputStream.read(buf.baseAddress!, maxLength: buf.count)
      }
      print("read \(readSize)")
      if readSize > 0 {
        print("in packet: \(inputBuffer[0..<readSize])")
        if readSize > 12 && inputBuffer[8] == 0x02 && inputBuffer[11] == 0x01 {
          // TODO: zhuowei - dump the RequestEncryption protobuf
          try! Data(inputBuffer[0..<readSize]).write(to: URL(filePath: "received.bin"))
        }
      }
      print(l2cap.inputStream.streamStatus.rawValue)
    }
  }
}

let starcruiser = Starcruiser()
RunLoop.main.run()
