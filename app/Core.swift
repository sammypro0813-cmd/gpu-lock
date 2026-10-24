import AVFoundation
import Darwin
import Foundation

// Blocking calls into the Rust core run here, one at a time.
let coreQueue = DispatchQueue(label: "gpulock.core")
// Pairing blocks for minutes, so it gets its own queue.
let pairingQueue = DispatchQueue(label: "gpulock.pairing")

struct CoreError: Error {
    let message: String
}

struct ConditionProfile: Codable, Hashable, Identifiable {
    let identifier: String
    let description: String
    var id: String { identifier }
}

struct ConditionGroup: Codable, Hashable, Identifiable {
    let identifier: String
    let profiles: [ConditionProfile]
    var id: String { identifier }

    var isGPU: Bool {
        identifier.localizedCaseInsensitiveContains("gpu")
            || profiles.contains { $0.description.localizedCaseInsensitiveContains("gpu") }
    }
}

struct ActiveCondition: Equatable {
    let group: String
    let profile: String
}

/// Runs blocking work on the core queue and resumes with its result.
func runOnCore<T>(_ work: @escaping () -> T) async -> T {
    await withCheckedContinuation { continuation in
        coreQueue.async { continuation.resume(returning: work()) }
    }
}

enum Core {
    /// Shown on the iPhone as "Pair with GPU Lock". The pairing identity is derived from it.
    static let hostName = "GPU Lock"
    /// LocalDevVPN loops this address back to the iPhone itself.
    static let deviceIP = "10.7.0.1"

    static var documents: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    static var pairingFileURL: URL {
        documents.appendingPathComponent("pairing.plist")
    }

    static var ddiDirectory: String? {
        Bundle.main.url(forResource: "DDI", withExtension: nil)?.path
    }

    static func take(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer else { return nil }
        defer { gl_string_free(pointer) }
        return String(cString: pointer)
    }

    static func decodeGroups(_ json: String) -> [ConditionGroup] {
        (try? JSONDecoder().decode([ConditionGroup].self, from: Data(json.utf8))) ?? []
    }

    static func start(port: UInt16, pairingPath: String, ddiDir: String?) -> Result<[ConditionGroup], CoreError> {
        var error: UnsafeMutablePointer<CChar>?
        let call: (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? = { ddi in
            Core.deviceIP.withCString { ip in
                pairingPath.withCString { path in
                    Core.hostName.withCString { host in
                        gl_start(ip, port, path, host, ddi, &error)
                    }
                }
            }
        }
        let result: UnsafeMutablePointer<CChar>?
        if let ddiDir {
            result = ddiDir.withCString { call($0) }
        } else {
            result = call(nil)
        }
        if let json = Core.take(result) {
            return .success(decodeGroups(json))
        }
        return .failure(CoreError(message: take(error) ?? "알 수 없는 연결 오류"))
    }

    static func enable(group: String, profile: String) -> Result<Void, CoreError> {
        var error: UnsafeMutablePointer<CChar>?
        let code = group.withCString { g in
            profile.withCString { p in gl_enable(g, p, &error) }
        }
        return code == 0 ? .success(()) : .failure(CoreError(message: take(error) ?? "조건을 켜지 못했습니다"))
    }

    static func disable() -> Result<Void, CoreError> {
        var error: UnsafeMutablePointer<CChar>?
        let code = gl_disable(&error)
        return code == 0 ? .success(()) : .failure(CoreError(message: take(error) ?? "조건을 끄지 못했습니다"))
    }

    static func refresh() -> Result<[ConditionGroup], CoreError> {
        var error: UnsafeMutablePointer<CChar>?
        if let json = take(gl_refresh(&error)) {
            return .success(decodeGroups(json))
        }
        return .failure(CoreError(message: take(error) ?? "연결 확인 실패"))
    }

    static func stop() {
        gl_stop()
    }
}

// MARK: - Finding this iPhone's remote pairing port

/// The iPhone advertises its remote pairing service as `_remotepairing._tcp`.
/// We browse for it and pick the one whose address belongs to this iPhone.
final class RemotePairingPort: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    static let fallback: UInt16 = 49152

    private let browser = NetServiceBrowser()
    private var services: [NetService] = []
    private var resolved: [(port: UInt16, local: Bool)] = []
    private let localAddresses = RemotePairingPort.ownAddresses()

    /// Blocks for up to `timeout` seconds, running this thread's run loop.
    /// Call off the main thread.
    static func find(timeout: TimeInterval = 4) -> (port: UInt16, how: String) {
        let finder = RemotePairingPort()
        finder.run(timeout: timeout)
        if let mine = finder.resolved.first(where: { $0.local }) {
            return (port: mine.port, how: "Bonjour")
        }
        if finder.resolved.count == 1, let only = finder.resolved.first {
            return (port: only.port, how: "Bonjour")
        }
        return (port: fallback, how: "기본값")
    }

    private func run(timeout: TimeInterval) {
        browser.delegate = self
        browser.schedule(in: .current, forMode: .default)
        browser.searchForServices(ofType: "_remotepairing._tcp.", inDomain: "local.")
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline && !resolved.contains(where: { $0.local }) {
            _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }
        browser.stop()
        services.forEach { $0.stop() }
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        services.append(service)
        service.delegate = self
        service.schedule(in: .current, forMode: .default)
        service.resolve(withTimeout: 3)
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        guard (1...65535).contains(sender.port) else { return }
        let addresses = (sender.addresses ?? []).compactMap(RemotePairingPort.ipString)
        let local = addresses.contains { localAddresses.contains($0) }
        resolved.append((port: UInt16(sender.port), local: local))
    }

    private static func ipString(_ data: Data) -> String? {
        data.withUnsafeBytes { raw -> String? in
            guard let base = raw.baseAddress else { return nil }
            let sa = base.assumingMemoryBound(to: sockaddr.self)
            let hostLength = Int(NI_MAXHOST)
            var host = [CChar](repeating: 0, count: hostLength)
            let ok = getnameinfo(sa, socklen_t(data.count), &host, socklen_t(hostLength), nil, 0, NI_NUMERICHOST)
            guard ok == 0 else { return nil }
            return String(cString: host).components(separatedBy: "%").first
        }
    }

    private static func ownAddresses() -> Set<String> {
        var result = Set<String>()
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return result }
        defer { freeifaddrs(list) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            if let addr = entry.pointee.ifa_addr {
                let family = Int32(addr.pointee.sa_family)
                if family == AF_INET || family == AF_INET6 {
                    let length = family == AF_INET
                        ? MemoryLayout<sockaddr_in>.size
                        : MemoryLayout<sockaddr_in6>.size
                    if let ip = ipString(Data(bytes: addr, count: length)) {
                        result.insert(ip)
                    }
                }
            }
            cursor = entry.pointee.ifa_next
        }
        return result
    }
}

// MARK: - Staying alive in the background

/// Plays silence (mixed with other apps' audio) so iOS keeps the app running
/// while you are in Settings or in a benchmark. The GPU condition only stays
/// on while this app holds its connection.
final class KeepAlive {
    static let shared = KeepAlive()

    private var engine = AVAudioEngine()
    private var player = AVAudioPlayerNode()
    private var users = 0
    private var timer: Timer?

    func retain() {
        users += 1
        if users == 1 { start() }
    }

    func release() {
        users = max(users - 1, 0)
        if users == 0 { stop() }
    }

    private func start() {
        do {
            engine.stop()
            engine = AVAudioEngine()
            player = AVAudioPlayerNode()
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, options: [.mixWithOthers])
            try session.setActive(true)
            engine.attach(player)
            let format = engine.mainMixerNode.outputFormat(forBus: 0)
            engine.connect(player, to: engine.mainMixerNode, format: format)
            if let silence = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: AVAudioFrameCount(format.sampleRate)) {
                silence.frameLength = silence.frameCapacity
                player.scheduleBuffer(silence, at: nil, options: .loops)
            }
            try engine.start()
            player.play()
        } catch {
            NSLog("[GPULock] keep-alive audio failed: \(error)")
        }
        timer?.invalidate()
        let t = Timer(timeInterval: 5, repeats: true) { _ in KeepAlive.shared.recover() }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    private func recover() {
        guard users > 0, !engine.isRunning || !player.isPlaying else { return }
        do {
            try AVAudioSession.sharedInstance().setActive(true)
            if !engine.isRunning { try engine.start() }
            player.play()
        } catch {
            // Another app holds the audio session right now; try again later.
        }
    }

    private func stop() {
        timer?.invalidate()
        timer = nil
        player.stop()
        engine.stop()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }
}
