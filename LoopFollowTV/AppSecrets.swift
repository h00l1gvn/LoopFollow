import Foundation

struct AppSecrets {
    let nightscoutURL: URL
    let nightscoutToken: String
    let apnsKeyID: String
    let apnsTeamID: String
    let apnsPrivateKey: String
    let otpSecret: String

    static func load() throws -> AppSecrets {
        guard let url = Bundle.main.url(forResource: "LoopTVSecrets", withExtension: "plist"),
              let data = try? Data(contentsOf: url),
              let values = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: String]
        else { throw AppFailure.configuration("This personal build is missing its private configuration.") }
        func required(_ key: String) throws -> String {
            guard let value = values[key]?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
                throw AppFailure.configuration("The build is missing \(key).")
            }
            return value
        }
        let rawURL = try required("NightscoutURL")
        guard let nightscoutURL = URL(string: rawURL) else { throw AppFailure.configuration("The Nightscout address is invalid.") }
        return try AppSecrets(nightscoutURL: nightscoutURL,
                              nightscoutToken: required("NightscoutToken"),
                              apnsKeyID: required("APNSKeyID"),
                              apnsTeamID: required("APNSTeamID"),
                              apnsPrivateKey: required("APNSPrivateKey"),
                              otpSecret: values["OTPSecret"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
    }
}
