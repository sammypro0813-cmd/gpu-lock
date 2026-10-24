import SwiftUI

@main
struct GPULockApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @ObservedObject private var engine = Engine.shared

    var body: some View {
        NavigationStack {
            List {
                pairingSection
                connectionSection
                if engine.link == .connected {
                    gpuSection
                    allConditionsSection
                }
                if let error = engine.lastError {
                    Section("오류") {
                        Text(error).foregroundStyle(.red).textSelection(.enabled)
                    }
                }
                logSection
            }
            .navigationTitle("GPU Lock")
        }
    }

    // MARK: 1. Pairing

    private var pairingSection: some View {
        Section {
            switch engine.pairing {
            case .idle, .done, .failed:
                if engine.hasPairingFile {
                    Label("페어링 파일 있음", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                } else {
                    Label("아직 페어링 안 됨", systemImage: "link.badge.plus")
                }
                if case .failed(let message) = engine.pairing {
                    Text(message).font(.footnote).foregroundStyle(.red)
                }
                Button(engine.hasPairingFile ? "다시 페어링" : "페어링 시작") {
                    engine.startPairing()
                }
            case .waiting:
                Label("페어링 대기 중", systemImage: "antenna.radiowaves.left.and.right")
                Text("설정 › 개인정보 보호 및 보안 › 개발자 모드로 가서 맨 아래 **Pair with GPU Lock**을 누르세요. PIN은 알림과 이 화면에 나옵니다.")
                    .font(.footnote)
                Button("취소", role: .cancel) { engine.cancelPairing() }
            case .pin(let code):
                Text("설정 화면에 이 PIN을 입력하세요").font(.footnote)
                Text(code)
                    .font(.system(size: 44, weight: .bold, design: .monospaced))
                    .frame(maxWidth: .infinity)
                    .textSelection(.enabled)
                Button("취소", role: .cancel) { engine.cancelPairing() }
            }
        } header: {
            Text("1. 페어링")
        }
    }

    // MARK: 2. Connection

    private var connectionSection: some View {
        Section {
            switch engine.link {
            case .disconnected:
                Label("연결 안 됨", systemImage: "bolt.horizontal.circle")
            case .connecting:
                HStack {
                    ProgressView()
                    Text("연결 중… (처음엔 1분쯤 걸릴 수 있음)")
                }
            case .connected:
                Label("연결됨", systemImage: "bolt.horizontal.circle.fill").foregroundStyle(.green)
            case .failed(let message):
                Label("연결 실패", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(message).font(.footnote)
            }

            if engine.link == .connected {
                Button("연결 끊기", role: .destructive) {
                    Task { await engine.disconnect() }
                }
            } else {
                Button("연결") {
                    Task { await engine.connect() }
                }
                .disabled(engine.link == .connecting || !engine.hasPairingFile)
            }
            Toggle("끊기면 자동으로 다시 연결", isOn: $engine.autoReconnect)
        } header: {
            Text("2. 연결")
        } footer: {
            Text("LocalDevVPN을 켠 상태에서 누르세요. 이 앱을 위로 밀어 완전히 종료하면 설정한 조건도 꺼집니다.")
        }
    }

    // MARK: 3. GPU

    private var gpuSection: some View {
        Section {
            if engine.gpuGroups.isEmpty {
                Text("이 기기의 조건 목록에 GPU 항목이 없습니다. 아래 전체 목록을 확인하세요.")
                    .font(.footnote)
            }
            ForEach(engine.gpuGroups) { group in
                ForEach(group.gpuProfiles) { profile in
                    profileRow(group, profile)
                }
            }
            if engine.active != nil {
                Button("조건 끄기", role: .destructive) {
                    Task { await engine.disableCondition() }
                }
                .disabled(engine.busy)
            }
        } header: {
            Text("3. GPU 성능 상태")
        } footer: {
            Text("원하는 단계를 누르면 켜집니다. 켠 채로 3DMark로 가서 측정하세요.")
        }
    }

    private var allConditionsSection: some View {
        Section("전체 조건 목록") {
            ForEach(engine.groups) { group in
                DisclosureGroup(group.identifier) {
                    ForEach(group.profiles) { profile in
                        profileRow(group, profile)
                    }
                }
            }
        }
    }

    private func profileRow(_ group: ConditionGroup, _ profile: ConditionProfile) -> some View {
        let isOn = engine.active == ActiveCondition(group: group.identifier, profile: profile.identifier)
        return Button {
            Task { await engine.enable(group, profile) }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(profile.description.isEmpty ? profile.identifier : profile.description)
                    Text(profile.identifier).font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                if isOn {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                }
            }
        }
        .disabled(engine.busy)
    }

    // MARK: Log

    private var logSection: some View {
        Section("로그") {
            if engine.logs.isEmpty {
                Text("아직 없음").foregroundStyle(.secondary)
            }
            ForEach(Array(engine.logs.suffix(80).enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
    }
}
