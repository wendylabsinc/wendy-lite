import CWendyLite

/// Central dispatch point for host-to-guest callback events.
///
/// Subsystems register handlers by ID. The exported `wendy_handle_callback`
/// C function routes each event to its registered handler.
public enum CallbackDispatch {
    private struct State {
        var ids: [Int32] = []
        var handlers: [(Int32, Int32, Int32) -> Void] = []
    }
    private static let state = _LockedBox(State())

    public static func register(_ handlerID: Int32, _ handler: @escaping (Int32, Int32, Int32) -> Void) {
        state.withLockedValue { s in
            s.ids.append(handlerID)
            s.handlers.append(handler)
        }
    }

    static func dispatch(_ handlerID: Int32, _ arg0: Int32, _ arg1: Int32, _ arg2: Int32) {
        // Snapshot the handler under lock, then invoke outside the lock so the
        // handler can freely call back into this module without re-entrant lock
        // acquisition concerns.
        let handler: ((Int32, Int32, Int32) -> Void)? = state.withLockedValue { s in
            for i in 0..<s.ids.count where s.ids[i] == handlerID {
                return s.handlers[i]
            }
            return nil
        }
        handler?(arg0, arg1, arg2)
    }
}

@used
@_cdecl("wendy_handle_callback")
func wendy_handle_callback(_ handlerID: Int32, _ arg0: Int32, _ arg1: Int32, _ arg2: Int32) {
    CallbackDispatch.dispatch(handlerID, arg0, arg1, arg2)
}
