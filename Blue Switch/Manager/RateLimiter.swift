import Foundation
import Network

/// Per-IP failure tracker. Five failures within a 60s window block the IP for
/// 15 minutes; blocked endpoints are rejected before any handshake work.
final class RateLimiter {
  // MARK: - Constants

  private static let windowSeconds: TimeInterval = 60
  private static let failureThreshold = 5
  private static let blockDuration: TimeInterval = 15 * 60

  // MARK: - State

  private let queue = DispatchQueue(label: "com.blueswitch.ratelimiter")
  private var failuresByIP: [String: [Date]] = [:]
  private var blocksByIP: [String: Date] = [:]

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

  /// Record an authentication / framing failure for `endpoint`.
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
      }
    }
  }

  // MARK: - Helpers

  private func gc(key: String) {
    let now = Date()
    if let until = blocksByIP[key], until <= now {
      blocksByIP.removeValue(forKey: key)
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

  /// Extracts a stable per-IP key. Strips IPv6 scope ids. Falls back to the
  /// full endpoint string for non-hostPort cases (still per-IP, just preserved
  /// verbatim instead of fail-open).
  private static func bucket(for endpoint: NWEndpoint?) -> String {
    guard let endpoint = endpoint else { return "unknown" }
    switch endpoint {
    case .hostPort(let host, _):
      let raw = host.debugDescription
      if let pct = raw.firstIndex(of: "%") {
        return String(raw[..<pct])
      }
      return raw
    default:
      return "\(endpoint)"
    }
  }
}
