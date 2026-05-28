import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Errors that can occur during pairing operations
enum PairingError: Error {
  case invalidCode
  case derivationFailed
  case keychainFailed(OSStatus)
  case notPaired
}

/// Manages the pre-shared key used to authenticate peer Blue Switch installs.
/// Persists the derived 32-byte key in the keychain; exposes a published
/// `isPaired` flag plus a short fingerprint suitable for visual verification.
final class PairingStore: ObservableObject {
  // MARK: - Singleton

  static let shared = PairingStore()

  // MARK: - Constants

  static let codeLength = 9
  static let codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  private static let pbkdfSalt = "BlueSwitch-PSK-v1"
  private static let pbkdfIterations: UInt32 = 600_000
  private static let pbkdfKeyLength = 32
  private static let keychainService = "com.blueswitch.psk-v1"
  private static let keychainAccount = "shared"

  // MARK: - Published State

  @Published private(set) var isPaired: Bool = false
  @Published private(set) var fingerprint: String? = nil

  // MARK: - Initialization

  private init() {
    refreshState()
  }

  // MARK: - Public API

  /// Returns the currently stored PSK, or nil if unpaired.
  func currentKey() -> SymmetricKey? {
    guard let data = readKeyData() else { return nil }
    return SymmetricKey(data: data)
  }

  /// Generates a random pairing code of `codeLength` characters from the
  /// Crockford Base32 alphabet (no I/L/O/U).
  static func generateCode() -> String {
    let alphabet = Array(codeAlphabet)
    var bytes = [UInt8](repeating: 0, count: codeLength)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    var result = ""
    for byte in bytes {
      result.append(alphabet[Int(byte) % alphabet.count])
    }
    return result
  }

  /// Returns a display form (`XXX-XXX-XXX`) for a 9-char code.
  static func formatCode(_ code: String) -> String {
    let normalized = normalize(code)
    guard normalized.count == codeLength else { return normalized }
    let chars = Array(normalized)
    return "\(String(chars[0...2]))-\(String(chars[3...5]))-\(String(chars[6...8]))"
  }

  /// Normalizes free-form user input: uppercase, strip dashes/spaces.
  static func normalize(_ input: String) -> String {
    let upper = input.uppercased()
    return upper.filter { codeAlphabet.contains($0) }
  }

  /// Validates that `code` is exactly `codeLength` chars in the alphabet.
  static func isValid(_ code: String) -> Bool {
    let normalized = normalize(code)
    guard normalized.count == codeLength else { return false }
    return normalized.allSatisfy { codeAlphabet.contains($0) }
  }

  /// Derives K from a pairing code and stores it in the keychain.
  func pair(withCode code: String) throws {
    let normalized = Self.normalize(code)
    guard Self.isValid(normalized) else { throw PairingError.invalidCode }
    let key = try Self.deriveKey(fromCode: normalized)
    try writeKeyData(key)
    refreshState()
  }

  /// Removes the stored PSK.
  func unpair() {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.keychainService,
      kSecAttrAccount as String: Self.keychainAccount,
    ]
    SecItemDelete(query as CFDictionary)
    refreshState()
  }

  // MARK: - Internal Helpers

  /// PBKDF2-HMAC-SHA256 derivation of the PSK from the pairing code.
  static func deriveKey(fromCode code: String) throws -> Data {
    guard let codeData = code.data(using: .utf8),
      let saltData = pbkdfSalt.data(using: .utf8)
    else {
      throw PairingError.derivationFailed
    }

    var derived = Data(count: pbkdfKeyLength)
    let status: Int32 = derived.withUnsafeMutableBytes { derivedBytes in
      saltData.withUnsafeBytes { saltBytes in
        codeData.withUnsafeBytes { codeBytes in
          CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            codeBytes.bindMemory(to: Int8.self).baseAddress,
            codeData.count,
            saltBytes.bindMemory(to: UInt8.self).baseAddress,
            saltData.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            pbkdfIterations,
            derivedBytes.bindMemory(to: UInt8.self).baseAddress,
            pbkdfKeyLength
          )
        }
      }
    }
    guard status == kCCSuccess else { throw PairingError.derivationFailed }
    return derived
  }

  /// First 4 bytes of SHA256(K), hex-encoded.
  static func fingerprint(forKey key: Data) -> String {
    let digest = SHA256.hash(data: key)
    let prefix = Array(digest).prefix(4)
    return prefix.map { String(format: "%02X", $0) }.joined()
  }

  // MARK: - Private Methods

  private func refreshState() {
    if let data = readKeyData() {
      isPaired = true
      fingerprint = Self.fingerprint(forKey: data)
    } else {
      isPaired = false
      fingerprint = nil
    }
  }

  private func readKeyData() -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.keychainService,
      kSecAttrAccount as String: Self.keychainAccount,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else { return nil }
    return data
  }

  private func writeKeyData(_ data: Data) throws {
    let delete: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.keychainService,
      kSecAttrAccount as String: Self.keychainAccount,
    ]
    SecItemDelete(delete as CFDictionary)

    let add: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.keychainService,
      kSecAttrAccount as String: Self.keychainAccount,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
      kSecValueData as String: data,
    ]
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw PairingError.keychainFailed(status)
    }
  }
}
