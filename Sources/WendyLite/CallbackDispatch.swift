import CWendyLite

/// Central dispatch point for host-to-guest callback events.
///
/// Subsystems register handlers by ID. The exported `wendy_handle_callback`
/// C function routes each event to its registered handler.
public enum CallbackDispatch {
    nonisolated(unsafe) private static var ids: [Int32] = []
    nonisolated(unsafe) private static var handlers: [(Int32, Int32, Int32) -> Void] = []

    public static func register(_ handlerID: Int32, _ handler: @escaping (Int32, Int32, Int32) -> Void) {
        ids.append(handlerID)
        handlers.append(handler)
    }

    static func dispatch(_ handlerID: Int32, _ arg0: Int32, _ arg1: Int32, _ arg2: Int32) {
        for i in 0..<ids.count where ids[i] == handlerID {
            handlers[i](arg0, arg1, arg2)
            return
        }
    }
}

@used
@_cdecl("wendy_handle_callback")
func wendy_handle_callback(_ handlerID: Int32, _ arg0: Int32, _ arg1: Int32, _ arg2: Int32) {
    CallbackDispatch.dispatch(handlerID, arg0, arg1, arg2)
}
