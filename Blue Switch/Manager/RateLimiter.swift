import Foundation
import Network

/// Per-IP failure tracker. Five failures within a 60s window block the IP for
/// 15 minutes; blocked endpoints are rejected before any handshake work.
/// Blocks persist to UserDefaults so a process restart can't reset the counter.
final class RateLimiter {
  // MARK: - Constants

  private static let windowSeconds: TimeInterval = 60
  private static let failureThreshold = 5
  private static let blockDuration: TimeInterval = 15 * 60
  private static let blocksKey = "com.blueswitch.ratelimiter.blocks"

  // MARK: - State

  private let queue = DispatchQueue(label: "com.blueswitch.ratelimiter")
  private var failuresByIP: [String: [Date]] = [:]
  private var blocksByIP: [String: Date] = [:]

  // MARK: - Init

  init() {
    blocksByIP = Self.loadBlocks()
  }

  // MARK: - Public API

  /// Returns whether the connection from `endpoint` should be accepted now.
  func shouldAccept(endpoint: NWEndpoint?) -> Bool {
    let key = Self.bucket(for: endpoint)
    return queue.sync {
      gc(key: key)
      if let until = blocksByIP[key], until > Date() {
        return false
      }
      return true
    }
  }

  /// Record an authentication failure for `endpoint`.
  func recordFailure(endpoint: NWEndpoint?) {
    let key = Self.bucket(for: endpoint)
    queue.sync {
      let now = Date()
      var list = failuresByIP[key, default: []]
      list.append(now)
      list = list.filter { $0 > now.addingTimeInterval(-Self.windowSeconds) }
      failuresByIP[key] = list
      if list.count >= Self.failureThreshold {
        blocksByIP[key] = now.addingTimeInterval(Self.blockDuration)
        failuresByIP[key] = []
        Self.saveBlocks(blocksByIP)
      }
    }
  }

  // MARK: - Persistence

  private static func loadBlocks() -> [String: Date] {
    guard let data = UserDefaults.standard.data(forKey: blocksKey),
      let dict = try? JSONDecoder().decode([String: Date].self, from: data)
    else { return [:] }
    let now = Date()
    return dict.filter { $0.value > now }
  }

  private static func saveBlocks(_ blocks: [String: Date]) {
    let now = Date()
    let pruned = blocks.filter { $0.value > now }
    guard let data = try? JSONEncoder().encode(pruned) else { return }
    UserDefaults.standard.set(data, forKey: blocksKey)
  }

  // MARK: - Helpers

  private func gc(key: String) {
    let now = Date()
    if let until = blocksByIP[key], until <= now {
      blocksByIP.removeValue(forKey: key)
      Self.saveBlocks(blocksByIP)
    }
    if var list = failuresByIP[key] {
      list = list.filter { $0 > now.addingTimeInterval(-Self.windowSeconds) }
      if list.isEmpty {
        failuresByIP.removeValue(forKey: key)
      } else {
        failuresByIP[key] = list
      }
    }
  }

  /// Canonicalizes an endpoint to a single per-IP key. IPv4-mapped IPv6
  /// addresses (`::ffff:1.2.3.4`) collapse to their IPv4 form so an attacker
  /// cannot get two failure budgets by alternating stacks. IPv6 scope
  /// suffixes (`%enX`) are stripped.
  private static func bucket(for endpoint: NWEndpoint?) -> String {
    guard let endpoint = endpoint else { return "unknown" }
    guard case .hostPort(let host, _) = endpoint else { return "unknown" }
    switch host {
    case .ipv4(let addr):
      return addr.debugDescription
    case .ipv6(let addr):
      let raw = addr.debugDescription
      let stripped: String
      if let pct = raw.firstIndex(of: "%") {
        stripped = String(raw[..<pct])
      } else {
        stripped = raw
      }
      if stripped.lowercased().hasPrefix("::ffff:") {
        let v4 = String(stripped.dropFirst("::ffff:".count))
        if v4.split(separator: ".").count == 4 {
          return v4
        }
      }
      return stripped
    case .name(let name, _):
      return name
    @unknown default:
      return "unknown"
    }
  }
}
