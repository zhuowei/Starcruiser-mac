// https://github.com/apple/swift-crypto/blob/87a9e066d9f996c98e895d1d202b5d372b6d9f0c/Sources/Crypto/Util/PrettyBytes.swift
import Foundation

let charA = UInt8(97 /* "a" */)

let char0 = UInt8(48 /* "0" */)

private func itoh(_ value: UInt8) -> UInt8 {
  return (value > 9) ? (charA + value - 10) : (char0 + value)
}

extension DataProtocol {
  var hexString: String {
    let hexLen = self.count * 2
    var hexChars = [UInt8](repeating: 0, count: hexLen)
    var offset = 0

    self.regions.forEach { (_) in
      for i in self {
        hexChars[Int(offset * 2)] = itoh((i >> 4) & 0xF)
        hexChars[Int(offset * 2 + 1)] = itoh(i & 0xF)
        offset += 1
      }
    }

    return String(decoding: hexChars, as: UTF8.self)
  }
}
