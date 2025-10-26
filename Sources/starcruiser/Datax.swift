import CryptoExtras
import CryptoKit
import Foundation

// Implementation of Meta Ray-Bans' Airshield + Datax protocol.
// WARNING: this implementation isn't actually secure and is trivial to bypass. Do not send actually private info through.
class Datax: NSObject, StreamDelegate {
  private let inputStream: InputStream
  private let outputStream: OutputStream
  private let ecKey = P256.KeyAgreement.PrivateKey()
  private var remoteRequestEncryptionMessage: Com_Oculus_Atc_RequestEncryption?
  private var localRequestEncryptionMessage: Com_Oculus_Atc_RequestEncryption?
  private var remoteEnableEncryptionMessage: Com_Oculus_Atc_EnableEncryption?
  private var localEnableEncryptionMessage: Com_Oculus_Atc_EnableEncryption?

  private var encryptionKey: SymmetricKey!
  private var decryptionKey: SymmetricKey!

  private var encryptionHmacKey: SymmetricKey!
  private var decryptionHmacKey: SymmetricKey!

  // are you seriously telling me CryptoKit has no CBC block update...
  private var encryptionNextIV = [UInt8](repeating: 0, count: 0x10)
  private var decryptionNextIV = [UInt8](repeating: 0, count: 0x10)

  private var encryptionHmacBase: Int = 0
  private var decryptionHmacBase: Int = 0

  init(inputStream: InputStream, outputStream: OutputStream) {
    self.inputStream = inputStream
    self.outputStream = outputStream
    super.init()
    self.inputStream.delegate = self
    self.inputStream.schedule(in: RunLoop.main, forMode: .default)
    self.outputStream.delegate = self
    self.outputStream.schedule(in: RunLoop.main, forMode: .default)
    self.inputStream.open()
    self.outputStream.open()

    sendInitialRequestEncryptionPacket()
  }

  func sendUnencrypted(data: [UInt8]) {
    print("send unencrypted: \(hexStringFor(data))")
    outputStream.write(data, maxLength: data.count)
  }

  func sendEncrypted(data: [UInt8]) {
    print("send encrypted: \(hexStringFor(data))")
    // TODO: zhuowei - pad data.
    let encryptedData = try! AES._CBC.encrypt(
      data, using: encryptionKey, iv: AES._CBC.IV(ivBytes: encryptionNextIV), noPadding: true)
    encryptionNextIV = [UInt8](encryptedData[(encryptedData.count - 16)...])
    let encryptedDataWith00Header: [UInt8] = [0x00] + encryptedData
    let hmacHeader: [UInt8] = [0x02, 0x02, 0x00, 0x00]
    let hmacBase: [UInt8] = withUnsafeBytes(of: encryptionHmacBase) { [UInt8]($0) }
    let packetHmac = HMAC<SHA256>.authenticationCode(
      for: hmacHeader + hmacBase + encryptedDataWith00Header, using: encryptionHmacKey)
    encryptionHmacBase &+= 1
    let outputPacketData: [UInt8] = [0x40] + [UInt8](packetHmac)[0..<8] + encryptedDataWith00Header
    sendUnencrypted(data: outputPacketData)
  }

  func handleReceivedUnencryptedPacket(data: [UInt8]) {
    print("unencrypted packet: \(data.hexString)")
    if data.count > 8 && data[0] == 0x80 && data[4] != 0x03 {
      let payloadHeaderOff = data[2] & 0x80 == 0x80 ? 8 : 4
      let protoData = Data(data[(payloadHeaderOff + 4)...])
      let protoType = Int(data[payloadHeaderOff + 3])
      switch protoType {
      case Com_Oculus_Atc_MessageTypeSetup.requestEncryption.rawValue:
        let msg = try! Com_Oculus_Atc_RequestEncryption(
          serializedBytes: protoData)
        print(msg)
        remoteRequestEncryptionMessage = msg
        sendEnableEncryptionPacket()
      case Com_Oculus_Atc_MessageTypeSetup.enableEncryption.rawValue:
        let msg = try! Com_Oculus_Atc_EnableEncryption(
          serializedBytes: protoData)
        print(msg)
        remoteEnableEncryptionMessage = msg
        handleEnableEncryption()
      default:
        print("unknown type \(protoType)")
      }
    }
  }

  func handleReceivedEncryptedPacket(data: [UInt8]) {
    print("encrypted packet: \(data.hexString)")
    let hmacHeader: [UInt8] = [0x02, 0x02, 0x00, 0x00]
    let hmacBase: [UInt8] = withUnsafeBytes(of: decryptionHmacBase) { [UInt8]($0) }
    let hmacInput = hmacHeader + hmacBase + [UInt8](data[(1 + 8)...])
    let packetHmac = HMAC<SHA256>.authenticationCode(
      for: hmacInput, using: encryptionHmacKey)
    decryptionHmacBase &+= 1
    print("hmac: \(hexStringFor(packetHmac))")
    let dataForDecryption = data[(1 + 8 + 1)...]
    // TODO: zhuowei - reject invalid hmac
    let decryptedData = try! AES._CBC.decrypt(
      dataForDecryption, using: encryptionKey, iv: AES._CBC.IV(ivBytes: decryptionNextIV),
      noPadding: true)
    decryptionNextIV = [UInt8](decryptedData[(decryptedData.count - 16)...])
    handleReceivedUnencryptedPacket(data: [UInt8](decryptedData))
  }

  func stream(
    _ aStream: Stream,
    handle eventCode: Stream.Event
  ) {
    print("stream event: \(aStream) \(eventCode)")
    if aStream == inputStream && eventCode == Stream.Event.hasBytesAvailable {
      var inputBuffer = [UInt8](repeating: 0, count: 0x1000)
      let readSize = inputBuffer.withUnsafeMutableBytes { buf in
        inputStream.read(buf.baseAddress!, maxLength: buf.count)
      }
      print("read \(readSize)")
      if readSize > 0 {
        print("in packet: \(inputBuffer[0..<readSize])")
        let packetData = [UInt8](inputBuffer[0..<readSize])
        if packetData.count >= 1 + 8 + 1 && packetData[0] == 0x40 {
          handleReceivedEncryptedPacket(data: packetData)
        } else {
          handleReceivedUnencryptedPacket(data: packetData)
        }
      }
      print("stream status: \(inputStream.streamStatus.rawValue)")
    } else if aStream == inputStream && eventCode == Stream.Event.errorOccurred {
      print("inputStream: error occurred")
    } else if aStream == outputStream && eventCode == Stream.Event.errorOccurred {
      print("outputStream: error occurred")
    } else if aStream == outputStream && eventCode == Stream.Event.endEncountered {
      print("outputStream: end encountered")
    }
  }

  func sendInitialRequestEncryptionPacket() {
    var request = Com_Oculus_Atc_RequestEncryption()
    request.publicKey = ecKey.publicKey.rawRepresentation
    request.challenge = Data("0123456789abcdef".utf8)  // TODO: zhuowei: randomly generate this
    request.ellipticCurve = 0
    request.supportedParameters = 31

    localRequestEncryptionMessage = request

    let protoData: [UInt8] = try! request.serializedBytes()
    let header: [UInt8] = [
      0x80, UInt8(protoData.count + 4), 0x80, 0x01,
      0x81, 0x00, 0x00, 0x05,
      0x02, 0x00, 0x00, 0x01,
    ]
    sendUnencrypted(data: header + protoData)
  }

  func sendEnableEncryptionPacket() {
    var request = Com_Oculus_Atc_EnableEncryption()
    request.publicKey = ecKey.publicKey.rawRepresentation
    request.seed = Data(repeating: 0x41, count: 0x20)  // TODO: zhuowei: randomly generate this
    request.iv = Data(repeating: 0x42, count: 0x10)  // TODO: zhuowei: randomly generate this
    request.base = 0x4142_4344  // TODO: zhuowei: randomly generate this
    request.parameters = 31

    localEnableEncryptionMessage = request
    let protoData: [UInt8] = try! request.serializedBytes()
    let header: [UInt8] = [
      0x80, UInt8(protoData.count + 4), 0x00, 0x01,
      0x02, 0x00, 0x00, 0x02,
    ]
    sendUnencrypted(data: header + protoData)
  }

  func handleEnableEncryption() {
    let sharedSecret = try! ecKey.sharedSecretFromKeyAgreement(
      with: try! P256.KeyAgreement.PublicKey(
        rawRepresentation: remoteEnableEncryptionMessage!.publicKey))
    print("dh: \(hexStringFor(sharedSecret))")
    encryptionKey = computeEncryptionKey(
      sharedSecret: sharedSecret, challenge: remoteRequestEncryptionMessage!.challenge,
      seed: localEnableEncryptionMessage!.seed)
    encryptionHmacKey = computeHmacKey(
      sharedSecret: sharedSecret, challenge: remoteRequestEncryptionMessage!.challenge,
      seed: localEnableEncryptionMessage!.seed)
    decryptionKey = computeEncryptionKey(
      sharedSecret: sharedSecret, challenge: localRequestEncryptionMessage!.challenge,
      seed: remoteEnableEncryptionMessage!.seed)
    decryptionHmacKey = computeHmacKey(
      sharedSecret: sharedSecret, challenge: localRequestEncryptionMessage!.challenge,
      seed: remoteEnableEncryptionMessage!.seed)

    encryptionNextIV = [UInt8](localEnableEncryptionMessage!.iv)
    decryptionNextIV = [UInt8](localEnableEncryptionMessage!.iv)

    // send first encrypted message...
    sendIdentityRequestPacket()
  }

  func sendIdentityRequestPacket() {
    let header: [UInt8] = [
      0x80, 0x08, 0x80, 0x02, 0x81, 0x00, 0x00, 0x24, 0x02, 0x00, 0x30, 0x00,
      0xc4, 0xc4, 0xc4, 0xc4,
    ]
    sendEncrypted(data: header)
  }
}

func hexStringFor(_ key: ContiguousBytes) -> String {
  return Data(
    key.withUnsafeBytes {
      [UInt8]($0)
    }
  ).hexString
}

func computeEncryptionKey(sharedSecret: SharedSecret, challenge: Data, seed: Data) -> SymmetricKey {
  let salt = SHA256.hash(data: challenge + seed)
  return sharedSecret.hkdfDerivedSymmetricKey(
    using: SHA256.self, salt: Data(salt), sharedInfo: Data("AirShield".utf8), outputByteCount: 0x20)
}

func computeHmacKey(sharedSecret: SharedSecret, challenge: Data, seed: Data) -> SymmetricKey {
  let salt = SHA256.hash(data: seed + challenge + "hmac_derive".utf8)
  return sharedSecret.hkdfDerivedSymmetricKey(
    using: SHA256.self, salt: Data(salt), sharedInfo: Data("AirShield".utf8), outputByteCount: 0x20)
}
