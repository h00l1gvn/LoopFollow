import Foundation

@MainActor
final class DashboardModel: ObservableObject {
    @Published var snapshot = LoopSnapshot()
    @Published var loading = false
    @Published var sending = false
    @Published var message: String?
    @Published var lastUpdated: Date?
    private var nightscout: NightscoutClient?
    private var apns: APNSClient?

    init() {
        do {
            let secrets = try AppSecrets.load()
            nightscout = NightscoutClient(secrets: secrets)
            apns = APNSClient(secrets: secrets)
        } catch { message = error.localizedDescription }
    }

    var commandsReady: Bool { snapshot.deviceToken?.isEmpty == false && snapshot.loopBundleIdentifier?.isEmpty == false }

    func refresh() async {
        guard let nightscout else { return }
        loading = true; defer { loading = false }
        do { snapshot = try await nightscout.loadSnapshot(); lastUpdated = Date(); message = nil }
        catch { message = error.localizedDescription }
    }

    func send(_ command: RemoteCommand) async {
        guard let apns, let token = snapshot.deviceToken, !token.isEmpty, let bundle = snapshot.loopBundleIdentifier, !bundle.isEmpty else {
            message = "Loop has not uploaded its command address to Nightscout yet."; return
        }
        sending = true; defer { sending = false }
        do { try await apns.send(command, deviceToken: token, bundleIdentifier: bundle); message = "Request delivered to Loop. Check Loop on the iPhone for the result." }
        catch { message = error.localizedDescription }
    }
}
