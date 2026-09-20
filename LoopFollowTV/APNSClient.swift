import CryptoKit
import Foundation

actor APNSClient {
    private let secrets: AppSecrets
    private var cachedJWT: (String, Date)?
    init(secrets: AppSecrets) { self.secrets = secrets }

    func send(_ command: RemoteCommand, deviceToken: String, bundleIdentifier: String) async throws {
        let payload = try commandPayload(command)
        let jwt = try authenticationToken()
        guard let url = URL(string: "https://api.push.apple.com/3/device/\(deviceToken)") else { throw AppFailure.configuration("The Loop device token is invalid.") }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.setValue("bearer \(jwt)", forHTTPHeaderField: "authorization")
        request.setValue(bundleIdentifier, forHTTPHeaderField: "apns-topic")
        request.setValue("alert", forHTTPHeaderField: "apns-push-type")
        request.setValue("10", forHTTPHeaderField: "apns-priority")
        request.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AppFailure.invalidResponse }
        guard http.statusCode == 200 else {
            let reason = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["reason"] as? String
            throw AppFailure.server("Apple Push Notification service returned \(reason ?? "HTTP \(http.statusCode)").")
        }
    }

    private func commandPayload(_ command: RemoteCommand) throws -> [String: Any] {
        let now = Date(), expiration = now.addingTimeInterval(300)
        var custom: [String: Any] = ["remote-address": "LoopFollow TV", "entered-by": "LoopFollow TV", "notes": "Sent via LoopFollow TV", "sent-at": iso(now), "expiration": iso(expiration)]
        let alert: String
        switch command {
        case let .carbs(grams, hours):
            custom["carbs-entry"] = grams; custom["absorption-time"] = hours; custom["start-time"] = iso(now); custom["otp"] = try currentOTP()
            alert = "Remote Carbs Entry: \(grams.formatted(.number.precision(.fractionLength(1)))) grams"
        case let .bolus(units):
            custom["bolus-entry"] = units; custom["otp"] = try currentOTP()
            alert = "Remote Bolus Entry: \(units.formatted(.number.precision(.fractionLength(2)))) U"
        case let .override(name, minutes):
            custom["override-name"] = name; if let minutes { custom["override-duration-minutes"] = minutes }
            alert = "\(name) Temporary Override"
        case .cancelOverride:
            custom["cancel-temporary-override"] = "true"; alert = "Cancel Temporary Override"
        }
        custom["aps"] = ["alert": alert, "content-available": 1, "interruption-level": "time-sensitive"]
        return custom
    }

    private func currentOTP() throws -> String {
        guard !secrets.otpSecret.isEmpty else { throw AppFailure.configuration("Carb and bolus controls need the one-time-password pairing from Loop.") }
        let key = SymmetricKey(data: Data(base32: secrets.otpSecret))
        var counter = UInt64(Date().timeIntervalSince1970 / 30).bigEndian
        let data = Data(bytes: &counter, count: 8)
        let bytes = Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
        let offset = Int(bytes.last! & 15)
        let value = (UInt32(bytes[offset] & 127) << 24) | (UInt32(bytes[offset + 1]) << 16) | (UInt32(bytes[offset + 2]) << 8) | UInt32(bytes[offset + 3])
        return String(format: "%06d", value % 1_000_000)
    }

    private func authenticationToken() throws -> String {
        if let cachedJWT, cachedJWT.1 > Date() { return cachedJWT.0 }
        let text = secrets.apnsPrivateKey.replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "").replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "").components(separatedBy: .whitespacesAndNewlines).joined()
        guard let data = Data(base64Encoded: text) else { throw AppFailure.configuration("The APNS private key is invalid.") }
        let key = try P256.Signing.PrivateKey(derRepresentation: data)
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": secrets.apnsKeyID]).base64URL
        let claims = try JSONSerialization.data(withJSONObject: ["iss": secrets.apnsTeamID, "iat": Int(Date().timeIntervalSince1970)]).base64URL
        let input = "\(header).\(claims)"
        let token = "\(input).\(try key.signature(for: Data(input.utf8)).rawRepresentation.base64URL)"
        cachedJWT = (token, Date().addingTimeInterval(3300))
        return token
    }

    private func iso(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return formatter.string(from: date)
    }
}

private extension Data {
    var base64URL: String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    init(base32 string: String) {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"); var bytes: [UInt8] = []; var buffer = 0; var bits = 0
        for character in string.uppercased() {
            guard let index = alphabet.firstIndex(of: character) else { continue }
            buffer = (buffer << 5) | index; bits += 5
            if bits >= 8 {
                bits -= 8
                bytes.append(UInt8((buffer >> bits) & 255))
                buffer &= bits == 0 ? 0 : (1 << bits) - 1
            }
        }
        self = Data(bytes)
    }
}
