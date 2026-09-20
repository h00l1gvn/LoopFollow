import Foundation

actor NightscoutClient {
    private let secrets: AppSecrets
    init(secrets: AppSecrets) { self.secrets = secrets }

    func loadSnapshot() async throws -> LoopSnapshot {
        async let entries = get("api/v1/entries.json", count: 1)
        async let statuses = get("api/v1/devicestatus.json", count: 1)
        async let profiles = get("api/v1/profile.json", count: 5)
        let (entryData, statusData, profileData) = try await (entries, statuses, profiles)
        var result = LoopSnapshot()
        result.glucose = parseGlucose(entryData)
        parseStatus(statusData, into: &result)
        parseProfiles(profileData, into: &result)
        return result
    }

    private func get(_ path: String, count: Int) async throws -> Data {
        var url = secrets.nightscoutURL
        for component in path.split(separator: "/") { url.appendPathComponent(String(component)) }
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { throw AppFailure.invalidResponse }
        parts.queryItems = [URLQueryItem(name: "count", value: String(count)), URLQueryItem(name: "token", value: secrets.nightscoutToken)]
        guard let finalURL = parts.url else { throw AppFailure.invalidResponse }
        var request = URLRequest(url: finalURL)
        request.timeoutInterval = 15
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AppFailure.invalidResponse }
        guard (200 ..< 300).contains(http.statusCode) else { throw AppFailure.server("Nightscout returned HTTP \(http.statusCode).") }
        return data
    }

    private func objects(_ data: Data) -> [[String: Any]] {
        (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] ?? []
    }

    private func parseGlucose(_ data: Data) -> GlucoseReading? {
        guard let record = objects(data).first, let glucose = number(record["sgv"]), glucose > 0 else { return nil }
        let milliseconds = number(record["date"]) ?? 0
        let date = milliseconds > 0 ? Date(timeIntervalSince1970: milliseconds / 1000) : parseDate(record["dateString"])
        return GlucoseReading(value: glucose, direction: record["direction"] as? String ?? "", date: date ?? .distantPast)
    }

    private func parseStatus(_ data: Data, into result: inout LoopSnapshot) {
        guard let status = objects(data).first else { return }
        let loop = status["loop"] as? [String: Any]
        let pump = status["pump"] as? [String: Any]
        result.iob = number((status["iob"] as? [String: Any])?["iob"] ?? loop?["iob"])
        result.cob = number((status["cob"] as? [String: Any])?["cob"] ?? loop?["cob"])
        result.reservoir = number(pump?["reservoir"])
        result.loopDate = parseDate(loop?["lastRun"] ?? status["created_at"])
        result.loopStatus = (loop?["name"] as? String) ?? (loop?["status"] as? String) ?? "Loop"
        result.activeOverride = (loop?["activeOverride"] as? [String: Any])?["name"] as? String
    }

    private func parseProfiles(_ data: Data, into result: inout LoopSnapshot) {
        for profile in objects(data) {
            let loopSettings = profile["loopSettings"] as? [String: Any]
            result.deviceToken = result.deviceToken ?? profile["deviceToken"] as? String ?? loopSettings?["deviceToken"] as? String
            result.loopBundleIdentifier = result.loopBundleIdentifier ?? profile["bundleIdentifier"] as? String ?? loopSettings?["bundleIdentifier"] as? String
            result.overrideNames += findOverrideNames(profile)
        }
        result.overrideNames = Array(Set(result.overrideNames)).sorted()
    }

    private func findOverrideNames(_ value: Any) -> [String] {
        if let dictionary = value as? [String: Any] {
            return dictionary.flatMap { key, child in
                let direct = key.lowercased().contains("override") ? ((child as? [[String: Any]])?.compactMap { $0["name"] as? String } ?? []) : []
                return direct + findOverrideNames(child)
            }
        }
        return (value as? [Any])?.flatMap(findOverrideNames) ?? []
    }

    private func number(_ value: Any?) -> Double? {
        (value as? NSNumber)?.doubleValue ?? (value as? String).flatMap(Double.init)
    }

    private func parseDate(_ value: Any?) -> Date? {
        if let value = value as? NSNumber { return Date(timeIntervalSince1970: value.doubleValue / 1000) }
        guard let string = value as? String else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: string) ?? ISO8601DateFormatter().date(from: string)
    }
}
