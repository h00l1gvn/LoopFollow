import SwiftUI

@main
struct LoopFollowTVApp: App {
    @StateObject private var model = DashboardModel()
    var body: some Scene {
        WindowGroup { RootView().environmentObject(model).preferredColorScheme(.dark) }
    }
}
