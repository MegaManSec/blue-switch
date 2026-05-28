import SwiftUI

/// View responsible for displaying and managing miscellaneous application settings
struct OtherSettingsView: View {
  // MARK: - Properties

  @Environment(\.openURL) private var openURL

  // MARK: - View Content

  /// Form content containing setting options
  private var formContent: some View {
    Form {
      Section {
        SettingsRowView(
          title: "License Information",
          help: "Open the project license in your browser.",
          action: showLicenseInfo
        )
      }
    }
  }

  var body: some View {
    if #available(macOS 13.0, *) {
      formContent
        .formStyle(.grouped)
    } else {
      formContent
        .padding()
    }
  }

  // MARK: - Private Methods

  private func showLicenseInfo() {
    guard let url = URL(string: "https://github.com/MegaManSec/blue-switch/blob/main/LICENSE")
    else { return }
    openURL(url)
  }
}

// MARK: - Supporting Views

/// A reusable row component for settings items
private struct SettingsRowView: View {
  // MARK: - Properties

  let title: String
  let help: String
  let action: () -> Void

  // MARK: - View Content

  var body: some View {
    Button(action: action) {
      HStack {
        Text(title)
        Spacer()
        Image(systemName: "chevron.right")
          .foregroundColor(.secondary)
      }
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .help(help)
  }
}

// MARK: - Preview

#Preview {
  OtherSettingsView()
}
