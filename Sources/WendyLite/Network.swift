import CWendyLite

// MARK: - WiFi

public enum WiFi {
    @discardableResult
    @inline(__always)
    public static func connect(ssid: UnsafePointer<CChar>, ssidLength: Int32, password: UnsafePointer<CChar>, passwordLength: Int32) -> Int32 {
        wifi_connect(ssid, ssidLength, password, passwordLength)
    }

    @discardableResult
    @inline(__always)
    public static func disconnect() -> Int32 {
        wifi_disconnect()
    }

    @inline(__always)
    public static func status() -> Int32 {
        wifi_status()
    }

    @inline(__always)
    public static func getIP(buffer: UnsafeMutablePointer<CChar>, length: Int32) -> Int32 {
        wifi_get_ip(buffer, length)
    }

    @inline(__always)
    public static func rssi() -> Int32 {
        wifi_rssi()
    }

    @discardableResult
    @inline(__always)
    public static func startAP(
        ssid: UnsafePointer<CChar>,
        ssidLength: Int32,
        password: UnsafePointer<CChar>,
        passwordLength: Int32,
        channel: Int32
    ) -> Int32 {
        wifi_ap_start(ssid, ssidLength, password, passwordLength, channel)
    }

    @discardableResult
    @inline(__always)
    public static func stopAP() -> Int32 {
        wifi_ap_stop()
    }
}

// MARK: - Sockets

public enum SocketDomain: Int32 {
    case inet = 2
}

public enum SocketType: Int32 {
    case stream = 1
    case dgram = 2
}

public enum Net {
    @inline(__always)
    public static func socket(domain: SocketDomain = .inet, type: SocketType, protocol proto: Int32 = 0) -> Int32 {
        net_socket(domain.rawValue, type.rawValue, proto)
    }

    @discardableResult
    @inline(__always)
    public static func connect(fd: Int32, ip: UnsafePointer<CChar>, ipLength: Int32, port: Int32) -> Int32 {
        net_connect(fd, ip, ipLength, port)
    }

    @discardableResult
    @inline(__always)
    public static func bind(fd: Int32, port: Int32) -> Int32 {
        net_bind(fd, port)
    }

    @discardableResult
    @inline(__always)
    public static func listen(fd: Int32, backlog: Int32) -> Int32 {
        net_listen(fd, backlog)
    }

    @inline(__always)
    public static func accept(fd: Int32) -> Int32 {
        net_accept(fd)
    }

    @inline(__always)
    public static func send(fd: Int32, data: UnsafePointer<CChar>, length: Int32) -> Int32 {
        net_send(fd, data, length)
    }

    @inline(__always)
    public static func recv(fd: Int32, buffer: UnsafeMutablePointer<CChar>, length: Int32) -> Int32 {
        net_recv(fd, buffer, length)
    }

    @discardableResult
    @inline(__always)
    public static func close(fd: Int32) -> Int32 {
        net_close(fd)
    }
}

// MARK: - DNS

public enum DNS {
    @inline(__always)
    public static func resolve(
        hostname: UnsafePointer<CChar>,
        hostnameLength: Int32,
        resultBuffer: UnsafeMutablePointer<CChar>,
        resultLength: Int32
    ) -> Int32 {
        dns_resolve(hostname, hostnameLength, resultBuffer, resultLength)
    }
}

// MARK: - TLS

public enum TLS {
    @inline(__always)
    public static func connect(host: UnsafePointer<CChar>, hostLength: Int32, port: Int32) -> Int32 {
        tls_connect(host, hostLength, port)
    }

    @inline(__always)
    public static func send(fd: Int32, data: UnsafePointer<CChar>, length: Int32) -> Int32 {
        tls_send(fd, data, length)
    }

    @inline(__always)
    public static func recv(fd: Int32, buffer: UnsafeMutablePointer<CChar>, length: Int32) -> Int32 {
        tls_recv(fd, buffer, length)
    }

    @discardableResult
    @inline(__always)
    public static func close(fd: Int32) -> Int32 {
        tls_close(fd)
    }
}
