import Network
import SwiftUI

/// Legacy connection error type kept for source compatibility with older
/// callers. Real I/O happens in `IncomingConnection` / `OutgoingConnection`.
enum ConnectionError: Error {
  case sendFailed(Error)
  case receiveFailed(Error)
  case connectionFailed(Error)
  case notPaired
}
