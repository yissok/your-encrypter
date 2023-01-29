import Foundation

extension Data {
    
    var bytes: [UInt8] {
        return [UInt8](self)
    }
    
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = "%02hhx"
        return self.map { String(format: format, $0) }.joined()
    }
    
    init?(hexEncodedString string: String) {
        let strip = CharacterSet(charactersIn: " <>\n\t")
        let input = string.unicodeScalars.filter { !strip.contains($0) }.map { $0.utf16 }.joined()
        func decodeNibble(u: UInt16) -> UInt8? {
            switch(u) {
            case 0x30 ... 0x39:
                return UInt8(u - 0x30)
            case 0x41 ... 0x46:
                return UInt8(u - 0x41 + 10)
            case 0x61 ... 0x66:
                return UInt8(u - 0x61 + 10)
            default:
                return nil
            }
        }

        self.init(capacity: input.count/2)
        var even = true
        var byte: UInt8 = 0
        for c in input {
            guard let val = decodeNibble(u: c) else {
                return nil
                
            }
            if even {
                byte = val << 4
            } else {
                byte += val
                self.append(byte)
            }
            even = !even
        }
        guard even else {
            return nil
            
        }
    }
}

internal extension String {
    var dataFromHexEncoding: Data? {
        return Data(hexEncodedString: self)!
    }
    
    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }
}

extension Array where Element == UInt8 {
    var data: Data {
        return Data(self)
    }
}
