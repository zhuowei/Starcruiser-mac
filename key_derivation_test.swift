import CryptoKit
import Foundation

// https://github.com/zhuowei/meta-ray-ban-android-app-frida/blob/da106a15c154ec38c15e73321ff07eb1b95242e7/notes/dump_pairing_notes.txt
// Self = Meta AI app, Remote = SimStella

let selfChallenge: [UInt8] = [
  0xc7, 0x50, 0x51, 0xfb, 0x3e, 0x50, 0x14, 0x2b, 0xa1, 0x0c, 0x15, 0xa0, 0x23, 0x77, 0x7c, 0x6b,
]

let remoteSeed: [UInt8] = [UInt8](repeating: 0x41, count: 0x20)

let decryptHKDFSalt = SHA256.hash(data: selfChallenge + remoteSeed)

let sharedSecret: [UInt8] = [
  0xf2, 0xf6, 0xf1, 0xf1, 0xa5, 0x6f, 0xb5, 0x21, 0x22, 0xec, 0x33, 0x8e,
  0xd8, 0x87, 0x33, 0x8b, 0x42, 0xb9, 0x76, 0x29, 0x02, 0x53, 0xdb, 0xd6,
  0xf4, 0x8f, 0x3c, 0xc0, 0xb1, 0x5b, 0x2b, 0xa8,
]

let decryptionKey = HKDF<SHA256>.deriveKey(
  inputKeyMaterial: SymmetricKey(data: sharedSecret), salt: Data(decryptHKDFSalt),
  info: Data("AirShield".utf8), outputByteCount: 0x20)

print(
  decryptionKey.withUnsafeBytes {
    [UInt8]($0)
  })

// Should be
// 7a0b4af830  d7 0b 81 65 36 01 bb c4 6f 13 c6 74 93 24 fa 2b  ...e6...o..t.$.+
// 7a0b4af840  68 0a f0 06 45 92 a2 c6 63 a0 89 1d 7a 43 87 5d  h...E...c...zC.] 256

let remoteChallenge: [UInt8] = [UInt8]("0123456789abcdef".utf8)

let selfSeed: [UInt8] = [
  0xc5, 0x8e, 0x0f, 0x4b, 0xf2, 0x91, 0xa0, 0xb2, 0xf5, 0x0a, 0x40, 0x95,
  0x5b, 0x0b, 0xd5, 0x3c, 0x9c, 0x7f, 0xd5, 0xa9, 0xf5, 0xfd, 0xbf, 0x7b,
  0x14, 0x27, 0x2e, 0xfe, 0xd5, 0x85, 0xca, 0x14,
]

let encryptHKDFSalt = SHA256.hash(data: remoteChallenge + selfSeed)

let encryptionKey = HKDF<SHA256>.deriveKey(
  inputKeyMaterial: SymmetricKey(data: sharedSecret), salt: Data(encryptHKDFSalt),
  info: Data("AirShield".utf8), outputByteCount: 0x20)

print(
  encryptionKey.withUnsafeBytes {
    [UInt8]($0)
  })

// should be 2f72596312c1120bf869dd69b0c6b4aa6cc05981723a45a4bb294343a11793cc

let encryptHMACSalt = SHA256.hash(data: selfSeed + remoteChallenge + "hmac_derive".utf8)

let encryptHMACKey = HKDF<SHA256>.deriveKey(
  inputKeyMaterial: SymmetricKey(data: sharedSecret), salt: Data(encryptHMACSalt),
  info: Data("AirShield".utf8), outputByteCount: 0x20)

print(
  encryptHMACKey.withUnsafeBytes {
    [UInt8]($0)
  })

let packet: [UInt8] = [
  0x40, 0xf4, 0xd0, 0x0b, 0xc5, 0xa2, 0x2d, 0x9e, 0xcd, 0x00, 0x55, 0xff,
  0x7a, 0x63, 0xea, 0x6a, 0xc9, 0xf1, 0x72, 0x37, 0x21, 0xff, 0xa9, 0xd7,
  0xf4, 0xa7,
]

let encryptedDataWith00Header = packet[(1 + 8)...]

let hmacHeader: [UInt8] = [0x02, 0x02, 0x00, 0x00]
let selfBase: [UInt8] = [0x80, 0x8b, 0x8d, 0xba]
let packetHMAC = HMAC<SHA256>.authenticationCode(
  for: hmacHeader + selfBase + encryptedDataWith00Header, using: encryptHMACKey)
print(packetHMAC)
// first 8 bytes should be f4d00bc5a22d9
