import Foundation

struct GlucoseReading: Equatable {
    let value: Double
    let direction: String
    let date: Date
}

struct LoopSnapshot: Equatable {
    var glucose: GlucoseReading?
    var iob: Double?
    var cob: Double?
    var reservoir: Double?
    var loopDate: Date?
    var loopStatus = "Waiting for Loop"
    var activeOverride: String?
    var deviceToken: String?
    var loopBundleIdentifier: String?
    var overrideNames: [String] = []
}

enum RemoteCommand: Equatable {
    case carbs(grams: Double, absorptionHours: Double)
    case bolus(units: Double)
    case override(name: String, minutes: Int?)
    case cancelOverride

    var title: String {
        switch self {
        case let .carbs(grams, _): return "Enter \(grams.formatted(.number.precision(.fractionLength(0)))) g carbs"
        case let .bolus(units): return "Request \(units.formatted(.number.precision(.fractionLength(2)))) U bolus"
        case let .override(name, _): return "Start \(name) override"
        case .cancelOverride: return "Cancel temporary override"
        }
    }

    var detail: String {
        switch self {
        case let .carbs(_, hours): return "Absorption time: \(hours.formatted(.number.precision(.fractionLength(1)))) hours"
        case .bolus: return "Loop will receive this as a remote bolus request."
        case let .override(_, minutes): return minutes.map { "Duration: \($0) minutes" } ?? "Use the preset duration."
        case .cancelOverride: return "Loop will receive a request to stop the active override."
        }
    }
}

enum AppFailure: LocalizedError {
    case configuration(String), invalidResponse, server(String)
    var errorDescription: String? {
        switch self {
        case let .configuration(value), let .server(value): return value
        case .invalidResponse: return "The server returned an unreadable response."
        }
    }
}
