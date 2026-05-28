import Foundation
import Network

/// Single-shot authenticated client connection to a peer Blue Switch instance.
/// Owns its NWConnection + SecureChannel; tears itself down once `run` is
/// complete (success or failure).
final class OutgoingConnection {
  // MARK: - Constants

  private static let connectionTimeout: TimeInterval = 5

  // MARK: - State

  private let connection: NWConnection
  private let pairingStore: PairingStore
  private let queue: DispatchQueue
  private var channel: SecureChannel?
  private var selfRef: OutgoingConnection?
  private var finished = false
  private var connectTimer: DispatchSourceTimer?

  // MARK: - Init

  init(
    host: String,
    port: UInt16,
    pairingStore: PairingStore = .shared,
    queue: DispatchQueue = DispatchQueue(label: "com.blueswitch.outgoing", qos: .userInitiated)
  ) {
    self.connection = NWConnection(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(integerLiteral: port),
      using: .tcp
    )
    self.pairingStore = pairingStore
    self.queue = queue
  }

  // MARK: - Public API

  /// Runs the handshake then invokes `body` with the live secure channel.
  /// `body` must call `done(_:)` to release the connection.
  func run(
    body: @escaping (SecureChannel, @escaping (Bool) -> Void) -> Void,
    completion: @escaping (Bool) -> Void
  ) {
    selfRef = self

    guard let psk = pairingStore.currentKey() else {
      print("OutgoingConnection: not paired, aborting send")
      completion(false)
      release()
      return
    }

    let channel = SecureChannel(
      connection: connection, role: .client, psk: psk, queue: queue
    )
    self.channel = channel

    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + Self.connectionTimeout)
    timer.setEventHandler { [weak self] in
      guard let self = self else { return }
      self.finish(success: false, completion: completion)
    }
    timer.resume()
    connectTimer = timer

    connection.stateUpdateHandler = { [weak self] state in
      guard let self = self else { return }
      switch state {
      case .ready:
        channel.performHandshake { result in
          switch result {
          case .success:
            self.connectTimer?.cancel()
            self.connectTimer = nil
            body(channel) { ok in
              self.finish(success: ok, completion: completion)
            }
          case .failure(let err):
            print("OutgoingConnection handshake failed: \(err)")
            self.finish(success: false, completion: completion)
          }
        }
      case .failed(let error):
        print("OutgoingConnection failed: \(error)")
        self.finish(success: false, completion: completion)
      case .cancelled:
        // No-op; finish handled explicitly.
        break
      default:
        break
      }
    }
    connection.start(queue: queue)
  }

  // MARK: - Helpers

  private func finish(success: Bool, completion: @escaping (Bool) -> Void) {
    guard !finished else { return }
    finished = true
    connectTimer?.cancel()
    connectTimer = nil
    channel?.cancel()
    connection.cancel()
    completion(success)
    release()
  }

  private func release() {
    queue.async { [weak self] in
      self?.selfRef = nil
    }
  }
}
