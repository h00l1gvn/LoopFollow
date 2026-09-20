import SwiftUI

struct RootView: View {
    @EnvironmentObject private var model: DashboardModel
    var body: some View {
        TabView {
            DashboardView().tabItem { Label("Dashboard", systemImage: "waveform.path.ecg") }
            ControlsView().tabItem { Label("Controls", systemImage: "slider.horizontal.3") }
        }
        .tint(.green)
        .task {
            await model.refresh()
            while !Task.isCancelled { try? await Task.sleep(nanoseconds: 60_000_000_000); await model.refresh() }
        }
        .alert("LoopFollow TV", isPresented: Binding(get: { model.message != nil }, set: { if !$0 { model.message = nil } })) {
            Button("OK", role: .cancel) { model.message = nil }
        } message: { Text(model.message ?? "") }
    }
}

private struct DashboardView: View {
    @EnvironmentObject private var model: DashboardModel
    var body: some View {
        VStack(alignment: .leading, spacing: 34) {
            HStack {
                Label("LoopFollow TV", systemImage: "circle.hexagongrid.fill").font(.largeTitle.bold()).foregroundStyle(.green)
                Spacer()
                Button { Task { await model.refresh() } } label: { Label(model.loading ? "Refreshing" : "Refresh", systemImage: "arrow.clockwise") }.disabled(model.loading)
            }
            HStack(spacing: 28) {
                StatusCard(title: "Glucose", value: glucoseText, detail: glucoseDetail, color: .green)
                StatusCard(title: "Loop", value: model.snapshot.loopStatus, detail: loopDetail, color: loopColor)
                StatusCard(title: "Insulin on board", value: decimal(model.snapshot.iob, " U"), detail: "IOB", color: .cyan)
                StatusCard(title: "Carbs on board", value: decimal(model.snapshot.cob, " g"), detail: "COB", color: .orange)
            }
            HStack(spacing: 28) {
                StatusCard(title: "Pump reservoir", value: decimal(model.snapshot.reservoir, " U"), detail: "Latest Nightscout value", color: .mint)
                StatusCard(title: "Override", value: model.snapshot.activeOverride ?? "None shown", detail: "Current Loop status", color: .purple)
                StatusCard(title: "Remote", value: model.commandsReady ? "Connected" : "Waiting", detail: model.commandsReady ? "Loop APNS ready" : "Needs a Loop upload", color: model.commandsReady ? .green : .yellow)
            }
            Text(model.lastUpdated.map { "Dashboard refreshed \($0.formatted(date: .omitted, time: .standard))" } ?? "Dashboard has not refreshed yet").font(.callout).foregroundStyle(.secondary)
        }.padding(70).background(Color.black.ignoresSafeArea())
    }
    private var glucoseText: String { model.snapshot.glucose.map { $0.value.formatted(.number.precision(.fractionLength(0))) } ?? "—" }
    private var glucoseDetail: String { model.snapshot.glucose.map { "\($0.direction) · \($0.date.formatted(.relative(presentation: .numeric)))" } ?? "Waiting for CGM data" }
    private var loopDetail: String { model.snapshot.loopDate?.formatted(.relative(presentation: .numeric)) ?? "Waiting for Loop data" }
    private var loopColor: Color { model.snapshot.loopDate.map { Date().timeIntervalSince($0) < 720 ? .green : .yellow } ?? .yellow }
    private func decimal(_ value: Double?, _ suffix: String) -> String { value.map { $0.formatted(.number.precision(.fractionLength(1))) + suffix } ?? "—" }
}

private struct StatusCard: View {
    let title: String, value: String, detail: String; let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title.uppercased()).font(.caption.bold()).foregroundStyle(.secondary)
            Text(value).font(.system(size: 45, weight: .bold, design: .rounded)).lineLimit(1).minimumScaleFactor(0.55)
            Text(detail).font(.callout).foregroundStyle(.secondary).lineLimit(1)
        }.frame(maxWidth: .infinity, minHeight: 165, alignment: .leading).padding(26)
            .background(color.opacity(0.14), in: RoundedRectangle(cornerRadius: 24))
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(color.opacity(0.55), lineWidth: 2))
    }
}

private struct ControlsView: View {
    @EnvironmentObject private var model: DashboardModel
    @State private var carbs = 20.0
    @State private var absorption = 3.0
    @State private var bolus = 0.5
    @State private var overrideMinutes = 60
    @State private var pending: RemoteCommand?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 32) {
                Text("Loop controls").font(.largeTitle.bold()).foregroundStyle(.green)
                Text("Every request opens a separate confirmation screen before it is sent to Loop.").foregroundStyle(.secondary)
                HStack(alignment: .top, spacing: 32) {
                    card("Carbs", "fork.knife") {
                        adjuster("\(Int(carbs)) g", minus: { carbs = max(1, carbs - 1) }, plus: { carbs = min(250, carbs + 1) })
                        adjuster("\(absorption.formatted(.number.precision(.fractionLength(1)))) hr", minus: { absorption = max(0.5, absorption - 0.5) }, plus: { absorption = min(8, absorption + 0.5) })
                        Button("Review carb entry") { pending = .carbs(grams: carbs, absorptionHours: absorption) }
                    }
                    card("Bolus", "drop.fill") {
                        adjuster("\(bolus.formatted(.number.precision(.fractionLength(2)))) U", minus: { bolus = max(0.05, bolus - 0.05) }, plus: { bolus = min(20, bolus + 0.05) })
                        Button("Review bolus request") { pending = .bolus(units: bolus) }
                    }
                }
                card("Temporary overrides", "figure.run") {
                    adjuster("\(overrideMinutes) minutes", minus: { overrideMinutes = max(15, overrideMinutes - 15) }, plus: { overrideMinutes = min(720, overrideMinutes + 15) })
                    if model.snapshot.overrideNames.isEmpty { Text("Preset buttons appear after Loop uploads its profile.").foregroundStyle(.secondary) }
                    else { HStack { ForEach(model.snapshot.overrideNames, id: \.self) { name in Button(name) { pending = .override(name: name, minutes: overrideMinutes) } } } }
                    Button("Review cancel override", role: .destructive) { pending = .cancelOverride }
                }
            }.padding(70)
        }.background(Color.black.ignoresSafeArea()).disabled(!model.commandsReady || model.sending)
            .sheet(item: Binding(get: { pending.map(CommandItem.init) }, set: { if $0 == nil { pending = nil } })) { item in
                ConfirmationView(command: item.command, confirm: { pending = nil; Task { await model.send(item.command) } }, cancel: { pending = nil })
            }
    }

    private func card<Content: View>(_ title: String, _ image: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 22) { Label(title, systemImage: image).font(.title2.bold()); content() }
            .frame(maxWidth: .infinity, alignment: .leading).padding(30).background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 24))
    }

    private func adjuster(_ value: String, minus: @escaping () -> Void, plus: @escaping () -> Void) -> some View {
        HStack(spacing: 18) {
            Button(action: minus) { Image(systemName: "minus") }
            Text(value).font(.title3.monospacedDigit()).frame(minWidth: 150)
            Button(action: plus) { Image(systemName: "plus") }
        }
    }
}

private struct CommandItem: Identifiable { let id = UUID(); let command: RemoteCommand }

private struct ConfirmationView: View {
    let command: RemoteCommand; let confirm: () -> Void; let cancel: () -> Void
    var body: some View {
        VStack(spacing: 34) {
            Image(systemName: "exclamationmark.circle.fill").font(.system(size: 70)).foregroundStyle(.yellow)
            Text("Confirm Loop request").font(.largeTitle.bold()); Text(command.title).font(.title); Text(command.detail).foregroundStyle(.secondary)
            HStack(spacing: 30) { Button("Cancel", role: .cancel, action: cancel); Button("Send to Loop", action: confirm).tint(.green) }
        }.padding(80).frame(minWidth: 900, minHeight: 600).background(Color.black)
    }
}
