#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>

#include "bleconn_darwin.h"

/* The wendy-lite BLE info service, 4E57454E-4459-0002-000x-000000000000.
 * Kept in step with components/wendy_ble/src/wendy_ble.c. */
static NSString *const kServiceUUID     = @"4E57454E-4459-0002-0000-000000000000";
static NSString *const kPSMCharUUID     = @"4E57454E-4459-0002-0001-000000000000";
static NSString *const kDeviceIDUUID    = @"4E57454E-4459-0002-0002-000000000000";
static NSString *const kDeviceNameUUID  = @"4E57454E-4459-0002-0003-000000000000";
static NSString *const kDisplayNameUUID = @"4E57454E-4459-0002-0004-000000000000";
static NSString *const kMTLSUUID        = @"4E57454E-4459-0002-0005-000000000000";

static void copy_cstr(char *dst, NSString *src) {
    if (!dst) return;
    dst[0] = '\0';
    if (!src) return;
    strlcpy(dst, [src UTF8String], WBLE_STR_CAP);
}

/* ── Scanner ─────────────────────────────────────────────────────────── */

@interface WendyBLEScanner : NSObject <CBCentralManagerDelegate>
@property (strong) CBCentralManager *central;
@property (strong) dispatch_queue_t queue;
@property (strong) dispatch_semaphore_t readySema;
@property (strong) NSMutableDictionary<NSString *, NSMutableDictionary *> *found;
@property (strong) NSLock *lock;
@property wble_err state;
@end

@implementation WendyBLEScanner

- (instancetype)init {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("sh.wendy.lite.ble.scan", DISPATCH_QUEUE_SERIAL);
        _readySema = dispatch_semaphore_create(0);
        _found = [NSMutableDictionary dictionary];
        _lock = [[NSLock alloc] init];
        _state = WBLE_OK;
    }
    return self;
}

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    switch (central.state) {
        case CBManagerStatePoweredOn:
            self.state = WBLE_OK;
            break;
        case CBManagerStateUnauthorized:
            self.state = WBLE_ERR_UNAUTHORIZED;
            break;
        case CBManagerStatePoweredOff:
            self.state = WBLE_ERR_POWERED_OFF;
            break;
        default:
            return; // transient; wait for a terminal state
    }
    dispatch_semaphore_signal(self.readySema);
}

- (void)centralManager:(CBCentralManager *)central
 didDiscoverPeripheral:(CBPeripheral *)peripheral
     advertisementData:(NSDictionary<NSString *, id> *)adv
                  RSSI:(NSNumber *)rssi {
    NSString *key = peripheral.identifier.UUIDString;

    [self.lock lock];
    NSMutableDictionary *entry = self.found[key];
    if (!entry) {
        entry = [NSMutableDictionary dictionary];
        self.found[key] = entry;
    }
    entry[@"rssi"] = rssi;

    /* peripheral.name is CoreBluetooth's cached GAP name and can be stale, so
     * the advertised local name wins whenever it is present. */
    NSString *local = adv[CBAdvertisementDataLocalNameKey];
    if (local.length > 0) {
        entry[@"name"] = local;
    } else if (!entry[@"name"] && peripheral.name.length > 0) {
        entry[@"name"] = peripheral.name;
    }

    NSData *mfg = adv[CBAdvertisementDataManufacturerDataKey];
    if (mfg.length > 2) {
        uint16_t company = 0;
        [mfg getBytes:&company length:2];
        if (company == 0xFFFF) {
            NSData *payload = [mfg subdataWithRange:NSMakeRange(2, mfg.length - 2)];
            NSString *devID = [[NSString alloc] initWithData:payload
                                                     encoding:NSUTF8StringEncoding];
            if (devID.length > 0) {
                entry[@"id"] = devID;
            }
        }
    }
    [self.lock unlock];
}

@end

int wble_scan(int timeout_ms, wble_scan_item *items, int max_items, wble_err *err) {
    @autoreleasepool {
        WendyBLEScanner *s = [[WendyBLEScanner alloc] init];
        s.central = [[CBCentralManager alloc] initWithDelegate:s queue:s.queue];

        if (dispatch_semaphore_wait(s.readySema,
                                    dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
            if (err) *err = WBLE_ERR_TIMEOUT;
            return -1;
        }
        if (s.state != WBLE_OK) {
            if (err) *err = s.state;
            return -1;
        }

        /* Duplicates on purpose: the first report carries the advertising
         * payload only, and the scan response (name, device id) merges in on
         * subsequent reports. */
        [s.central scanForPeripheralsWithServices:@[[CBUUID UUIDWithString:kServiceUUID]]
                                          options:@{CBCentralManagerScanOptionAllowDuplicatesKey: @YES}];

        [NSThread sleepForTimeInterval:(double)timeout_ms / 1000.0];
        [s.central stopScan];

        [s.lock lock];
        int n = 0;
        for (NSString *key in s.found) {
            if (n >= max_items) break;
            NSMutableDictionary *e = s.found[key];
            copy_cstr(items[n].identifier, key);
            copy_cstr(items[n].local_name, e[@"name"]);
            copy_cstr(items[n].device_id, e[@"id"]);
            items[n].rssi = [e[@"rssi"] intValue];
            n++;
        }
        [s.lock unlock];

        if (err) *err = WBLE_OK;
        return n;
    }
}

/* ── Connection ──────────────────────────────────────────────────────── */

@interface WendyBLEConn : NSObject <CBCentralManagerDelegate, CBPeripheralDelegate, NSStreamDelegate>
@property (strong) CBCentralManager *central;
@property (strong) CBPeripheral *peripheral;
@property (strong) dispatch_queue_t queue;
@property (strong) NSString *targetUUID;

@property (strong) dispatch_semaphore_t readySema;
@property (strong) dispatch_semaphore_t connectSema;
@property (strong) dispatch_semaphore_t discoverSema;
@property (strong) dispatch_semaphore_t readSema;
@property wble_err state;
@property BOOL connected;
@property BOOL connectFailed;
@property int pendingCharDiscovery;
@property int pendingReads;

@property (strong) CBL2CAPChannel *l2capChannel;
@property (strong) dispatch_semaphore_t l2capSema;
@property (strong) dispatch_semaphore_t recvSema;
@property (strong) NSMutableData *recvBuffer;
@property (strong) NSLock *recvLock;
@property (strong) NSThread *ioThread;
@property BOOL ioRunning;
@property BOOL outputReady;
@property BOOL l2capFailed;
@property NSInteger writeResult;
@end

@implementation WendyBLEConn

- (instancetype)init {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("sh.wendy.lite.ble.conn", DISPATCH_QUEUE_SERIAL);
        _readySema = dispatch_semaphore_create(0);
        _connectSema = dispatch_semaphore_create(0);
        _discoverSema = dispatch_semaphore_create(0);
        _readSema = dispatch_semaphore_create(0);
        _l2capSema = dispatch_semaphore_create(0);
        _recvSema = dispatch_semaphore_create(0);
        _recvBuffer = [NSMutableData data];
        _recvLock = [[NSLock alloc] init];
        _state = WBLE_OK;
    }
    return self;
}

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    switch (central.state) {
        case CBManagerStatePoweredOn:  self.state = WBLE_OK; break;
        case CBManagerStateUnauthorized: self.state = WBLE_ERR_UNAUTHORIZED; break;
        case CBManagerStatePoweredOff: self.state = WBLE_ERR_POWERED_OFF; break;
        default: return;
    }
    dispatch_semaphore_signal(self.readySema);

    if (self.state != WBLE_OK || !self.targetUUID) return;

    /* CoreBluetooth shares its peripheral cache across managers in a process,
     * so a device just seen by the scanner is retrievable without re-scanning
     * — which also avoids a timeout if it stopped advertising in between. */
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:self.targetUUID];
    if (uuid) {
        NSArray<CBPeripheral *> *known = [central retrievePeripheralsWithIdentifiers:@[uuid]];
        if (known.count > 0) {
            self.peripheral = known[0];
            self.peripheral.delegate = self;
            [central connectPeripheral:self.peripheral options:nil];
            return;
        }
    }
    [central scanForPeripheralsWithServices:@[[CBUUID UUIDWithString:kServiceUUID]]
                                    options:@{CBCentralManagerScanOptionAllowDuplicatesKey: @NO}];
}

- (void)centralManager:(CBCentralManager *)central
 didDiscoverPeripheral:(CBPeripheral *)peripheral
     advertisementData:(NSDictionary<NSString *, id> *)adv
                  RSSI:(NSNumber *)rssi {
    if (![peripheral.identifier.UUIDString isEqualToString:self.targetUUID]) return;
    [central stopScan];
    self.peripheral = peripheral;
    peripheral.delegate = self;
    [central connectPeripheral:peripheral options:nil];
}

- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)p {
    self.connected = YES;
    dispatch_semaphore_signal(self.connectSema);
}

- (void)centralManager:(CBCentralManager *)central
didFailToConnectPeripheral:(CBPeripheral *)p error:(NSError *)error {
    self.connectFailed = YES;
    dispatch_semaphore_signal(self.connectSema);
}

- (void)centralManager:(CBCentralManager *)central
didDisconnectPeripheral:(CBPeripheral *)p error:(NSError *)error {
    self.connected = NO;
    self.ioRunning = NO;
    dispatch_semaphore_signal(self.connectSema);
    dispatch_semaphore_signal(self.discoverSema);
    dispatch_semaphore_signal(self.readSema);
    dispatch_semaphore_signal(self.recvSema);
    dispatch_semaphore_signal(self.l2capSema);
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error {
    if (error || peripheral.services.count == 0) {
        dispatch_semaphore_signal(self.discoverSema);
        return;
    }
    self.pendingCharDiscovery = (int)peripheral.services.count;
    for (CBService *svc in peripheral.services) {
        [peripheral discoverCharacteristics:nil forService:svc];
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
didDiscoverCharacteristicsForService:(CBService *)service
             error:(NSError *)error {
    if (--self.pendingCharDiscovery <= 0) {
        dispatch_semaphore_signal(self.discoverSema);
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic
             error:(NSError *)error {
    if (--self.pendingReads <= 0) {
        dispatch_semaphore_signal(self.readSema);
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
didOpenL2CAPChannel:(CBL2CAPChannel *)channel error:(NSError *)error {
    if (error || !channel) {
        self.l2capFailed = YES;
        dispatch_semaphore_signal(self.l2capSema);
        return;
    }
    self.l2capChannel = channel;
    channel.inputStream.delegate = self;
    channel.outputStream.delegate = self;
    self.ioRunning = YES;
    self.ioThread = [[NSThread alloc] initWithTarget:self
                                            selector:@selector(ioThreadMain)
                                              object:nil];
    [self.ioThread start];
}

/* Both streams live on this thread's run loop. CBL2CAP output-stream writes
 * must be issued from the thread that owns the run loop: writing from any
 * other thread returns -1 even when the stream reports itself open. */
- (void)ioThreadMain {
    @autoreleasepool {
        NSRunLoop *rl = [NSRunLoop currentRunLoop];
        [self.l2capChannel.inputStream scheduleInRunLoop:rl forMode:NSDefaultRunLoopMode];
        [self.l2capChannel.outputStream scheduleInRunLoop:rl forMode:NSDefaultRunLoopMode];
        [self.l2capChannel.inputStream open];
        [self.l2capChannel.outputStream open];

        /* HasSpaceAvailable on the output stream is the stack's confirmation
         * that writes will be accepted; treat the channel as open only then. */
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5.0];
        while (!self.outputReady && !self.l2capFailed) {
            if ([[NSDate date] compare:deadline] != NSOrderedAscending) {
                self.l2capFailed = YES;
                break;
            }
            [rl runMode:NSDefaultRunLoopMode
             beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
        dispatch_semaphore_signal(self.l2capSema);

        while (self.ioRunning) {
            [rl runMode:NSDefaultRunLoopMode
             beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
        }

        [self.l2capChannel.inputStream close];
        [self.l2capChannel.inputStream removeFromRunLoop:rl forMode:NSDefaultRunLoopMode];
        [self.l2capChannel.outputStream close];
        [self.l2capChannel.outputStream removeFromRunLoop:rl forMode:NSDefaultRunLoopMode];
    }
}

- (void)performWrite:(NSData *)data {
    self.writeResult = [self.l2capChannel.outputStream write:data.bytes
                                                   maxLength:data.length];
}

- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)event {
    if (stream == self.l2capChannel.outputStream) {
        if (event == NSStreamEventHasSpaceAvailable) {
            self.outputReady = YES;
        } else if (event == NSStreamEventErrorOccurred ||
                   event == NSStreamEventEndEncountered) {
            self.l2capFailed = YES;
            self.ioRunning = NO;
            dispatch_semaphore_signal(self.recvSema);
        }
        return;
    }

    if (event == NSStreamEventHasBytesAvailable) {
        uint8_t buf[4096];
        NSInteger n = [(NSInputStream *)stream read:buf maxLength:sizeof(buf)];
        if (n > 0) {
            [self.recvLock lock];
            [self.recvBuffer appendBytes:buf length:n];
            [self.recvLock unlock];
            dispatch_semaphore_signal(self.recvSema);
        }
    } else if (event == NSStreamEventEndEncountered ||
               event == NSStreamEventErrorOccurred) {
        self.ioRunning = NO;
        dispatch_semaphore_signal(self.recvSema);
    }
}

- (CBCharacteristic *)findChar:(NSString *)uuid {
    CBUUID *want = [CBUUID UUIDWithString:uuid];
    for (CBService *svc in self.peripheral.services) {
        for (CBCharacteristic *chr in svc.characteristics) {
            if ([chr.UUID isEqual:want]) return chr;
        }
    }
    return nil;
}

@end

wble_conn wble_connect(const char *identifier, int timeout_ms, wble_err *err) {
    @autoreleasepool {
        WendyBLEConn *c = [[WendyBLEConn alloc] init];
        c.targetUUID = [NSString stringWithUTF8String:identifier];
        c.central = [[CBCentralManager alloc] initWithDelegate:c queue:c.queue];

        if (dispatch_semaphore_wait(c.readySema,
                                    dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
            if (err) *err = WBLE_ERR_TIMEOUT;
            return NULL;
        }
        if (c.state != WBLE_OK) {
            if (err) *err = c.state;
            return NULL;
        }

        if (dispatch_semaphore_wait(c.connectSema,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)) != 0) {
            if (err) *err = WBLE_ERR_TIMEOUT;
            return NULL;
        }
        if (!c.connected || c.connectFailed) {
            if (err) *err = WBLE_ERR_CONNECT;
            return NULL;
        }

        if (err) *err = WBLE_OK;
        return (__bridge_retained wble_conn)c;
    }
}

wble_err wble_read_info(wble_conn handle, int timeout_ms,
                        uint16_t *psm, uint8_t *mtls,
                        char *device_id, char *device_name, char *display_name) {
    @autoreleasepool {
        WendyBLEConn *c = (__bridge WendyBLEConn *)handle;
        if (!c.connected) return WBLE_ERR_DISCONNECTED;

        [c.peripheral discoverServices:@[[CBUUID UUIDWithString:kServiceUUID]]];
        if (dispatch_semaphore_wait(c.discoverSema,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)) != 0) {
            return WBLE_ERR_TIMEOUT;
        }

        NSArray<NSString *> *uuids = @[kPSMCharUUID, kDeviceIDUUID,
                                       kDeviceNameUUID, kDisplayNameUUID, kMTLSUUID];
        NSMutableArray<CBCharacteristic *> *chrs = [NSMutableArray array];
        for (NSString *u in uuids) {
            CBCharacteristic *chr = [c findChar:u];
            if (!chr) return WBLE_ERR_DISCOVER;
            [chrs addObject:chr];
        }

        c.pendingReads = (int)chrs.count;
        for (CBCharacteristic *chr in chrs) {
            [c.peripheral readValueForCharacteristic:chr];
        }
        if (dispatch_semaphore_wait(c.readSema,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)) != 0) {
            return WBLE_ERR_TIMEOUT;
        }

        NSData *v = chrs[0].value;
        if (psm) {
            if (v.length < 2) return WBLE_ERR_READ;
            uint16_t raw = 0;
            [v getBytes:&raw length:2];
            *psm = CFSwapInt16LittleToHost(raw);
        }
        copy_cstr(device_id, [[NSString alloc] initWithData:chrs[1].value
                                                   encoding:NSUTF8StringEncoding]);
        copy_cstr(device_name, [[NSString alloc] initWithData:chrs[2].value
                                                     encoding:NSUTF8StringEncoding]);
        copy_cstr(display_name, [[NSString alloc] initWithData:chrs[3].value
                                                      encoding:NSUTF8StringEncoding]);
        if (mtls) {
            uint8_t raw = 0;
            if (chrs[4].value.length >= 1) [chrs[4].value getBytes:&raw length:1];
            *mtls = raw;
        }
        return WBLE_OK;
    }
}

wble_err wble_open_l2cap(wble_conn handle, uint16_t psm, int timeout_ms) {
    @autoreleasepool {
        WendyBLEConn *c = (__bridge WendyBLEConn *)handle;
        if (!c.connected) return WBLE_ERR_DISCONNECTED;

        c.l2capFailed = NO;
        c.l2capChannel = nil;
        c.outputReady = NO;
        [c.peripheral openL2CAPChannel:psm];

        if (dispatch_semaphore_wait(c.l2capSema,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)) != 0) {
            return WBLE_ERR_TIMEOUT;
        }
        if (c.l2capFailed || !c.l2capChannel || !c.outputReady) {
            return WBLE_ERR_L2CAP;
        }
        return WBLE_OK;
    }
}

int wble_send(wble_conn handle, const uint8_t *data, int len) {
    @autoreleasepool {
        WendyBLEConn *c = (__bridge WendyBLEConn *)handle;
        if (!c.connected || !c.l2capChannel || !c.ioRunning) return -1;

        NSData *payload = [NSData dataWithBytes:data length:len];
        [c performSelector:@selector(performWrite:)
                  onThread:c.ioThread
                withObject:payload
             waitUntilDone:YES];
        return (int)c.writeResult;
    }
}

int wble_recv(wble_conn handle, uint8_t *buf, int cap, int timeout_ms) {
    @autoreleasepool {
        WendyBLEConn *c = (__bridge WendyBLEConn *)handle;

        for (;;) {
            [c.recvLock lock];
            NSUInteger avail = c.recvBuffer.length;
            if (avail > 0) {
                NSUInteger n = avail < (NSUInteger)cap ? avail : (NSUInteger)cap;
                memcpy(buf, c.recvBuffer.bytes, n);
                [c.recvBuffer replaceBytesInRange:NSMakeRange(0, n) withBytes:NULL length:0];
                [c.recvLock unlock];
                return (int)n;
            }
            [c.recvLock unlock];

            if (!c.ioRunning || !c.connected) return -1;

            if (dispatch_semaphore_wait(c.recvSema,
                    dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)) != 0) {
                return 0; // timeout; the caller decides whether to keep waiting
            }
        }
    }
}

void wble_close(wble_conn handle) {
    if (!handle) return;
    @autoreleasepool {
        WendyBLEConn *c = (__bridge_transfer WendyBLEConn *)handle;
        c.ioRunning = NO; // the I/O thread closes and unschedules both streams
        if (c.peripheral && c.connected) {
            [c.central cancelPeripheralConnection:c.peripheral];
        }
    }
}
