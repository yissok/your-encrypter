// credit for this goes to the kind apple engineer Quinn “The Eskimo!”
// https://developer.apple.com/forums/thread/687212

import Foundation
import CommonCrypto

/// Encrypts data using AES with PKCS#7 padding in CBC mode.
///
/// - note: PKCS#7 padding is also known as PKCS#5 padding.
///
/// - Parameters:
///   - key: The key to encrypt with; must be a supported size (128, 192, 256).
///   - iv: The initialisation vector; must be of size 16.
///   - plaintext: The data to encrypt; the PKCS#7 padding means there are no
///     constraints on its length.
/// - Returns: The encrypted data; it’s length with always be an even multiple of 16.

func QCCAESPadCBCEncrypt(key: [UInt8], iv: [UInt8], inputData: [UInt8]) throws -> [UInt8] {

    // The key size must be 128, 192, or 256.
    //
    // The IV size must match the block size.

    guard
        [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(key.count),
        iv.count == kCCBlockSizeAES128
    else {
        throw QCCError(code: kCCParamError)
    }

    // Padding can expand the data, so we have to allocate space for that.  The
    // rule for block cyphers, like AES, is that the padding only adds space on
    // encryption (on decryption it can reduce space, obviously, but we don't
    // need to account for that) and it will only add at most one block size
    // worth of space.

    var cyphertext = [UInt8](repeating: 0, count: inputData.count + kCCBlockSizeAES128)
    var cyphertextCount = 0
    let err = CCCrypt(
        CCOperation(kCCEncrypt),
        CCAlgorithm(kCCAlgorithmAES),
        CCOptions(kCCOptionPKCS7Padding),
        key, key.count,
        iv,
        inputData, inputData.count,
        &cyphertext, cyphertext.count,
        &cyphertextCount
    )
    guard err == kCCSuccess else {
        throw QCCError(code: err)
    }
    
    // The cyphertext can expand by up to one block but it doesn’t always use the full block,
    // so trim off any unused bytes.
    
    assert(cyphertextCount <= cyphertext.count)
    cyphertext.removeLast(cyphertext.count - cyphertextCount)
    assert(cyphertext.count.isMultiple(of: kCCBlockSizeAES128))
    
//    print("cyphertext    : "+cyphertext.data.hexEncodedString())
    return cyphertext
}

/// Decrypts data that was encrypted using AES with PKCS#7 padding in CBC mode.
///
/// - note: PKCS#7 padding is also known as PKCS#5 padding.
///
/// - Parameters:
///   - key: The key to encrypt with; must be a supported size (128, 192, 256).
///   - iv: The initialisation vector; must be of size 16.
///   - cyphertext: The encrypted data; it’s length must be an even multiple of
///     16.
/// - Returns: The decrypted data.

func QCCAESPadCBCDecrypt(key: [UInt8], iv: [UInt8], cyphertext: [UInt8]) throws -> [UInt8] {

    // The key size must be 128, 192, or 256.
    //
    // The IV size must match the block size.
    //
    // The ciphertext must be a multiple of the block size.

    guard
        [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(key.count),
        iv.count == kCCBlockSizeAES128,
        cyphertext.count.isMultiple(of: kCCBlockSizeAES128)
    else {
        throw QCCError(code: kCCParamError)
    }

    // Padding can expand the data on encryption, but on decryption the data can
    // only shrink so we use the cyphertext size as our plaintext size.

    var plaintext = [UInt8](repeating: 0, count: cyphertext.count)
    var plaintextCount = 0
    let err = CCCrypt(
        CCOperation(kCCDecrypt),
        CCAlgorithm(kCCAlgorithmAES),
        CCOptions(kCCOptionPKCS7Padding),
        key, key.count,
        iv,
        cyphertext, cyphertext.count,
        &plaintext, plaintext.count,
        &plaintextCount
    )
    guard err == kCCSuccess else {
        throw QCCError(code: err)
    }
    
    // Trim any unused bytes off the plaintext.
    
    assert(plaintextCount <= plaintext.count)
    plaintext.removeLast(plaintext.count - plaintextCount)

    return plaintext
}

/// Wraps `CCCryptorStatus` for use in Swift.

struct QCCError: Error {
    var code: CCCryptorStatus
}

extension QCCError {
    init(code: Int) {
        self.init(code: CCCryptorStatus(code))
    }
}

func generateRandomIv() -> Data? {
    return generateRandomBytes(16)
}

func generateRandomSalt() -> Data? {
    return generateRandomBytes(8)
}

func generateRandomBytes(_ n:Int) -> Data? {

    var keyData = Data(count: n)
    let result = keyData.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!)
    }
    if result == errSecSuccess {
        return keyData
    } else {
        print("Problem generating random bytes")
        return nil
    }
}

func baseAddNecessaryBase64EqualsPadding(_ str:String) -> String{
    var res = str
    if !(str.count % 4 == 0) {
        res = res + ("===").prefix(4 - (str.count % 4))
    }
    return res
}

func pbkdf2sha1(password: String, salt: String, keyByteCount: Int, rounds: Int) -> String? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: String, keyByteCount: Int, rounds: Int) -> String? {
    let passwordData = password.data(using: .utf8)!
    let saltData = salt.dataFromHexEncoding!
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)
    
    var localDerivedKeyData = derivedKeyData
    
    let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        saltData.withUnsafeBytes { saltBytes in
            
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, passwordData.count,
                saltBytes, saltData.count,
                hash,
                UInt32(rounds),
                derivedKeyBytes, localDerivedKeyData.count)
        }
    }
    if (derivationStatus != kCCSuccess) {
        print("Error: \(derivationStatus)")
        return nil;
    }
    
    return toHex(derivedKeyData)
}

private func toHex(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}













func createKey(password: String, saltstr:String) -> String{
    return (pbkdf2sha1(password: password, salt: saltstr, keyByteCount: 16, rounds: 1000)!)
}

func getBytesKey(_ key: String) -> [UInt8]{
//    print("key          : "+key)
    return key.dataFromHexEncoding!.bytes
}
//salt         : c26acebd045558ab
//key          : d2343b6a61d049fdb45a3ae85c0e0e71
//iv retrieved : 80566406dc3bc86bf96e9d7dbe45455f
// di 8ea32787ee558e0296580c96a024b88b
//    8ea32787ee558e0296580c96a024b88b
func encLite(password: String, input: String) -> String{
    let salt:[UInt8] = generateRandomSalt()!.bytes
//    print("salt         : "+salt.data.hexEncodedString())
    let saltstr:String = salt.data.hexEncodedString()
//    let saltstr:String = "c26acebd045558ab"
//    let salt:[UInt8] = saltstr.dataFromHexEncoding!.bytes
    let key:[UInt8] = getBytesKey(createKey(password: password, saltstr: saltstr))
    let iv:[UInt8] = generateRandomIv()!.bytes
//    let iv:[UInt8] = "80566406dc3bc86bf96e9d7dbe45455f".dataFromHexEncoding!.bytes
//    print("iv generated : "+iv.data.hexEncodedString())
    let inputData:[UInt8] = input.data(using: .utf8)!.bytes
//    print("inputData    : "+inputData.data.hexEncodedString())
    let cypheredBytes:[UInt8] = addSaltBytes(ivAndCypher: addIvBytes(cypheredBytes: try! QCCAESPadCBCEncrypt(key: key, iv: iv, inputData: inputData), iv: iv), salt: salt)
//    print("enc bytes    : "+cypheredBytes.data.hexEncodedString())
    let enc:String = cypheredBytes.data.base64EncodedString().toBase64().replacingOccurrences(of: "=", with: "")
//    print("enc          : "+enc)
    return enc
}

func decLite(password: String, input: String) -> String{
    let dataInput:[UInt8] = Data(base64Encoded: (baseAddNecessaryBase64EqualsPadding(input)).fromBase64()!)!.bytes
    let saltStr:String = getSaltBytes(dataInput: dataInput).data.hexEncodedString()
    let ivAndCypher:[UInt8] = Array(dataInput.dropFirst(8));
    let key:[UInt8] = getBytesKey(createKey(password: password, saltstr: saltStr))
    let iv:[UInt8] = getIvBytes(dataInput: ivAndCypher)
    let cypher:[UInt8] = Array(ivAndCypher.dropFirst(16));
//    print("input        : "+ivAndCypher.data.hexEncodedString())
    print("key          : "+key.data.hexEncodedString())
    print("iv retrieved : "+iv.data.hexEncodedString())
    print("dataInputAlon: "+cypher.data.hexEncodedString())
    var decBytes:[UInt8]
    do {
        decBytes = try QCCAESPadCBCDecrypt(key: key, iv: iv, cyphertext: cypher)
//        print("decBytes     : "+decBytes.data.hexEncodedString())
        let decryptedString = String(data: decBytes.data, encoding: .utf8) ?? "INVALID_FORMAT"
        return decryptedString
    } catch {
        return "INVALID_FORMAT"
    }
}

func encryptMessageWithDeets(input: String, password: String) -> String {
    let salt:[UInt8] = generateRandomSalt()!.bytes
    let saltstr:String = salt.data.hexEncodedString()
    let key:[UInt8] = getBytesKey(createKey(password: password, saltstr: saltstr))
    let iv:[UInt8] = generateRandomIv()!.bytes
    let inputData:[UInt8] = input.data(using: .utf8)!.bytes
    let cypheredBytes = try! QCCAESPadCBCEncrypt(key: key, iv: iv, inputData: inputData)
    let cypheredBytesWithIvAndSalt:[UInt8] = addSaltBytes(ivAndCypher: addIvBytes(cypheredBytes: cypheredBytes, iv: iv), salt: salt)
    let res1:String = cypheredBytes.data.hexEncodedString() + "\n\nkey: " + key.data.hexEncodedString()
    let res2:String = res1 + "\niv: " + iv.data.hexEncodedString()  + "\n\ngo to https://cryptii.com/ and select 'decode', 'block cipher', 'aes 128', 'CBC' and insert the key, the iv and the initial string input, view 'bytes' and hexadecimal\n\nor\n\nask andrea to add your email to the beta testers list for this app so you can decrypt from your shortcuts app"
    print(res2)
    return res2
}


func getIvBytes(dataInput: [UInt8]) -> [UInt8]{
    return Array(dataInput.prefix(16))
}

func getSaltBytes(dataInput: [UInt8]) -> [UInt8]{
    return Array(dataInput.prefix(8))
}


func addIvBytes(cypheredBytes:[UInt8], iv:[UInt8]) -> [UInt8]{
    return iv + cypheredBytes
}

func addSaltBytes(ivAndCypher:[UInt8], salt:[UInt8]) -> [UInt8]{
    return salt + ivAndCypher
}
