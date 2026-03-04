import CWendyLite

public enum GPIOMode: Int32 {
    case input = 0
    case output = 1
    case inputOutput = 2
}

public enum GPIOPull: Int32 {
    case none = 0
    case up = 1
    case down = 2
}

public enum GPIOInterruptEdge: Int32 {
    case rising = 1
    case falling = 2
    case anyEdge = 3
}

public enum GPIO {
    @discardableResult
    @inline(__always)
    public static func configure(pin: Int32, mode: GPIOMode, pull: GPIOPull = .none) -> Int32 {
        gpio_configure(pin, mode.rawValue, pull.rawValue)
    }

    @inline(__always)
    public static func read(pin: Int32) -> Int32 {
        gpio_read(pin)
    }

    @discardableResult
    @inline(__always)
    public static func write(pin: Int32, level: Int32) -> Int32 {
        gpio_write(pin, level)
    }

    @discardableResult
    @inline(__always)
    public static func setPWM(pin: Int32, frequencyHz: Int32, dutyPercent: Int32) -> Int32 {
        gpio_set_pwm(pin, frequencyHz, dutyPercent)
    }

    @inline(__always)
    public static func analogRead(pin: Int32) -> Int32 {
        gpio_analog_read(pin)
    }

    @discardableResult
    @inline(__always)
    public static func setInterrupt(pin: Int32, edge: GPIOInterruptEdge, handlerId: Int32) -> Int32 {
        gpio_set_interrupt(pin, edge.rawValue, handlerId)
    }

    @discardableResult
    @inline(__always)
    public static func clearInterrupt(pin: Int32) -> Int32 {
        gpio_clear_interrupt(pin)
    }
}
