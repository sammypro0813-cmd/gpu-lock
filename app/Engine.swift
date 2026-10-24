import Foundation
import SwiftUI
import UserNotifications
import dnssd

// C callbacks cannot capture anything, so they hop to the shared engine.
private let logCallback: GlLogCallback = { message, _ in
    guard let message else { return }
    let text = String(cString: message)
    Task { @MainActor in Engine.shared.log(text) }
}

private let pinCallback: GlPinCallback = { pin, _ in
    guard let pin else { return }
    let code = String(cString: pin)
    Task { @MainActor in Engine.shared.showPin(code) }
}

private let registerCallback: DNSServiceRegisterReply = { _, _, error, _, _, _, _ in
    guard error != DNSServiceErrorType(kDNSServiceErr_NoError) else { return }
    Task { @MainActor in Engine.shared.advertisingFailed(error) }
}

@MainActor
final class Engine: ObservableObject {
    static let shared = Engine()

    enum LinkState: Equatable {
        case disconnected
        case connecting
        case connected
        case failed(String)
    }

    enum PairState: Equatable {
        case idle
        case waiting
        case pin(String)
        case done(String)
        case failed(String)
    }

    @Published var link: LinkState = .disconnected
    @Published var pairing: PairState = .idle
    @Published var groups: [ConditionGroup] = []
    @Published var active: ActiveCondition?
    @Published var hasPairingFile = false
    @Published var autoReconnect = true
    @Published var busy = false
    @Published var lastError: String?
    @Published var logs: [String] = []

    /// What the user asked for; restored after an automatic reconnect.
    private var wanted: ActiveCondition?
    private var pairSession: OpaquePointer?
    private var registration: DNSServiceRef?
    private var watchdog: Timer?
    private var keepingAlive = false
    private var reconnecting = false

    private init() {
        gl_set_log_callback(logCallback, nil)
        hasPairingFile = FileManager.default.fileExists(atPath: Core.pairingFileURL.path)
    }

    var gpuGroups: [ConditionGroup] { groups.filter(\.isGPU) }

    func log(_ text: String) {
        let stamp = Date().formatted(date: .omitted, time: .standard)
        logs.append("\(stamp)  \(text)")
        if logs.count > 300 { logs.removeFirst(logs.count - 300) }
    }

    // MARK: Pairing

    func startPairing() {
        guard pairSession == nil else { return }
        lastError = nil
        var error: UnsafeMutablePointer<CChar>?
        guard let session = gl_pairing_new(Core.hostName, &error) else {
            pairing = .failed(Core.take(error) ?? "페어링을 시작하지 못했습니다")
            return
        }
        guard advertise(session) else {
            gl_pairing_free(session)
            return
        }
        pairSession = session
        pairing = .waiting
        refreshKeepAlive()
        requestNotifications()
        log("페어링 대기 중 (포트 \(gl_pairing_port(session)))")

        let path = Core.pairingFileURL.path
        pairingQueue.async {
            var name: UnsafeMutablePointer<CChar>?
            var error: UnsafeMutablePointer<CChar>?
            let code = path.withCString { gl_pairing_accept(session, pinCallback, nil, $0, &name, &error) }
            let deviceName = Core.take(name)
            let message = Core.take(error)
            Task { @MainActor in
                Engine.shared.pairingFinished(session: session, code: code, deviceName: deviceName, message: message)
            }
        }
    }

    func cancelPairing() {
        if let pairSession { gl_pairing_cancel(pairSession) }
    }

    func showPin(_ code: String) {
        pairing = .pin(code)
        log("PIN 표시됨")
        let content = UNMutableNotificationContent()
        content.title = "GPU Lock 페어링 PIN"
        content.body = "설정 화면에 \(code) 를 입력하세요"
        content.sound = .default
        let request = UNNotificationRequest(identifier: "gpulock.pin", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    func advertisingFailed(_ error: DNSServiceErrorType) {
        let message = error == DNSServiceErrorType(kDNSServiceErr_PolicyDenied)
            ? "로컬 네트워크 권한이 필요합니다. 설정 › 앱 › GPU Lock 에서 로컬 네트워크를 켜고 다시 시도하세요."
            : "로컬 네트워크에 알리지 못했습니다 (오류 \(error)). Wi-Fi가 켜져 있는지 확인하세요."
        log(message)
        pairing = .failed(message)
        cancelPairing()
    }

    private func pairingFinished(session: OpaquePointer, code: Int32, deviceName: String?, message: String?) {
        stopAdvertising()
        gl_pairing_free(session)
        pairSession = nil
        refreshKeepAlive()
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: ["gpulock.pin"])
        switch code {
        case 0:
            hasPairingFile = true
            pairing = .done(deviceName ?? "이 아이폰")
            log("페어링 완료: \(deviceName ?? "이 아이폰")")
        case 2:
            if case .failed = pairing {} else { pairing = .idle }
            log("페어링 취소됨")
        default:
            let text = message ?? "페어링 실패"
            pairing = .failed(text)
            log(text)
        }
    }

    private func advertise(_ session: OpaquePointer) -> Bool {
        var txt = TXTRecordRef()
        TXTRecordCreate(&txt, 0, nil)
        defer { TXTRecordDeallocate(&txt) }
        for index in 0..<gl_pairing_txt_count(session) {
            guard let key = gl_pairing_txt_key(session, index),
                  let value = gl_pairing_txt_value(session, index) else { continue }
            TXTRecordSetValue(&txt, key, UInt8(clamping: strlen(value)), value)
        }
        var ref: DNSServiceRef?
        let error = DNSServiceRegister(
            &ref, 0, 0,
            gl_pairing_service_name(session),
            "_remotepairing-pairable-host._tcp",
            nil, nil,
            gl_pairing_port(session).bigEndian,
            TXTRecordGetLength(&txt),
            TXTRecordGetBytesPtr(&txt),
            registerCallback,
            nil
        )
        guard error == DNSServiceErrorType(kDNSServiceErr_NoError), let ref else {
            pairing = .failed("로컬 네트워크에 알리지 못했습니다 (오류 \(error))")
            return false
        }
        _ = DNSServiceSetDispatchQueue(ref, .main)
        registration = ref
        return true
    }

    private func stopAdvertising() {
        if let registration { DNSServiceRefDeallocate(registration) }
        registration = nil
    }

    private func requestNotifications() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    // MARK: Connection

    func connect() async {
        guard link != .connecting, link != .connected else { return }
        guard hasPairingFile else {
            lastError = "먼저 페어링을 하세요."
            return
        }
        link = .connecting
        lastError = nil
        refreshKeepAlive()
        log("기기의 페어링 서비스 포트 찾는 중")
        let path = Core.pairingFileURL.path
        let ddi = Core.ddiDirectory
        let (found, result) = await runOnCore { () -> ((UInt16, String), Result<[ConditionGroup], CoreError>) in
            let found = RemotePairingPort.find()
            return ((found.port, found.how), Core.start(port: found.port, pairingPath: path, ddiDir: ddi))
        }
        log("사용한 포트: \(found.0) (\(found.1))")
        switch result {
        case .success(let list):
            groups = list
            active = nil
            link = .connected
            startWatchdog()
            refreshKeepAlive()
        case .failure(let error):
            link = .failed(error.message)
            lastError = error.message
            refreshKeepAlive()
        }
    }

    func disconnect() async {
        wanted = nil
        stopWatchdog()
        await runOnCore { Core.stop() }
        active = nil
        link = .disconnected
        refreshKeepAlive()
    }

    func enable(_ group: ConditionGroup, _ profile: ConditionProfile) async {
        guard link == .connected, !busy else { return }
        busy = true
        defer { busy = false }
        let target = ActiveCondition(group: group.identifier, profile: profile.identifier)
        let result = await runOnCore { Core.enable(group: target.group, profile: target.profile) }
        switch result {
        case .success:
            active = target
            wanted = target
            lastError = nil
        case .failure(let error):
            lastError = error.message
            log("켜기 실패: \(error.message)")
        }
    }

    func disableCondition() async {
        guard link == .connected, !busy else { return }
        busy = true
        defer { busy = false }
        let result = await runOnCore { Core.disable() }
        switch result {
        case .success:
            active = nil
            wanted = nil
        case .failure(let error):
            lastError = error.message
        }
    }

    // MARK: Watchdog

    private func startWatchdog() {
        stopWatchdog()
        let timer = Timer(timeInterval: 20, repeats: true) { _ in
            Task { @MainActor in await Engine.shared.checkConnection() }
        }
        RunLoop.main.add(timer, forMode: .common)
        watchdog = timer
    }

    private func stopWatchdog() {
        watchdog?.invalidate()
        watchdog = nil
    }

    private func checkConnection() async {
        guard link == .connected, !busy, !reconnecting else { return }
        let result = await runOnCore { Core.refresh() }
        if case .failure(let error) = result {
            log("연결이 끊어졌습니다: \(error.message)")
            active = nil
            stopWatchdog()
            if autoReconnect {
                await reconnect()
            } else {
                link = .failed(error.message)
                refreshKeepAlive()
            }
        }
    }

    private func reconnect() async {
        reconnecting = true
        refreshKeepAlive()
        defer {
            reconnecting = false
            refreshKeepAlive()
        }
        let restore = wanted
        await runOnCore { Core.stop() }
        link = .disconnected
        for attempt in 1...3 {
            log("다시 연결 시도 \(attempt)/3")
            await connect()
            if link == .connected { break }
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            if link != .connected { link = .disconnected }
        }
        guard link == .connected else {
            link = .failed("다시 연결하지 못했습니다")
            return
        }
        if let restore,
           let group = groups.first(where: { $0.identifier == restore.group }),
           let profile = group.profiles.first(where: { $0.identifier == restore.profile }) {
            await enable(group, profile)
        }
    }

    /// Keep running in the background while pairing, connected or reconnecting.
    private func refreshKeepAlive() {
        let on = pairSession != nil || reconnecting || link == .connected || link == .connecting
        guard on != keepingAlive else { return }
        keepingAlive = on
        if on { KeepAlive.shared.retain() } else { KeepAlive.shared.release() }
    }
}
