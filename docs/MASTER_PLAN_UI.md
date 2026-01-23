# Master Plan: Native Windows System UI for SafeOps Firewall V2

**Date:** 2026-01-23
**Goal:** Replace the web-based React dashboard with a high-performance, native Windows System UI.

---

## 1. Executive Summary

The SafeOps Firewall V2 requires a management interface that matches its high-performance backend. A native Windows UI offers superior integration with the OS, lower memory footprint compared to Electron/browser solutions, and a "built-in" feel that enterprise administrators expect.

We will evaluate **Go** and **Rust** ecosystems to select the best technology stack for this requirement.

---

## 2. Technology Evaluation

### Option A: Rust (Recommended for Performance & Look)
Rust offers excellent bindings to native Windows APIs and modern GUI frameworks.

| Framework | Pros | Cons | Verdict |
| :--- | :--- | :--- | :--- |
| **Tauri** | Extremely lightweight, uses system WebView (WebView2 on Windows). JS/TS frontend logic possible but can be kept minimal. | Technically hybrid (uses WebView), but feels native. | **Strong Contender** (If we want HTML/CSS styling power). |
| **Iced** | Pure Rust, Elm architecture, type-safe, cross-platform. | Custom look, not standard "Windows Controls" by default. | Good for custom tools. |
| **Slint** | Lightweight, embedded-friendly, custom UI language. | Smaller ecosystem. | Niche. |
| **Native Windows GUI (NWG)** | True Win32 API wrapper. Extremely fast and small. | "Old school" Windows look (Win32), harder to style modernly. | **Best for "System" feel.** |

### Option B: Go (Recommended for Speed of Development)
Go is the primary language of the backend, making code sharing (structs, gRPC clients) easier.

| Framework | Pros | Cons | Verdict |
| :--- | :--- | :--- | :--- |
| **Wails** | Go equivalent of Tauri. Uses system WebView2. Easy integration with Go backend code. | Hybrid approach. | **Strong Contender.** |
| **Fyne** | Pure Go, Material Design inspired. Renders its own widgets. | Non-native look (looks the same on Linux/Mac/Windows). | Good for consistency, bad for "Native Windows" feel. |
| **Walk** | Windows App Library Kit. Wrapper around Win32 API. | Older library, less active maintenance. | **Best for "System" feel.** |

---

## 3. Recommended Architecture: "Wails" or "Tauri"

Since we want a modern "System UI" that doesn't look like a 1995 Win32 app but still performs better than a full Chrome browser, **Wails (Go)** or **Tauri (Rust)** are the best choices.

**Decision: Wails (Go)**
*Reasoning:* The majority of the backend (Firewall Engine, Launcher, etc.) is in Go. Using Wails allows direct import of the gRPC client packages and data models defined in `src/`. It dramatically reduces context switching and code duplication.

### Proposed Architecture (Wails)

```mermaid
graph TD
    User[Admin User] -->|Interacts| GUI[Windows Native UI (WebView2)]
    GUI -->|Go Bindings| AppLogic[Go Application Logic]

    subgraph "SafeOps Backend"
        AppLogic -->|gRPC :50051| FE[Firewall Engine]
        AppLogic -->|gRPC :50055| DHCP[DHCP Monitor]
        AppLogic -->|REST :8081| NIC[NIC Management]
    end
```

**Key Features:**
1. **System Tray:** The app will minimize to the system tray (notification area).
2. **Native Notifications:** Use Windows native toast notifications for alerts.
3. **Single Binary:** Compiles to a single `.exe`.
4. **Low Resource:** Uses shared Edge Runtime (WebView2) already present on Windows.

---

## 4. Implementation Roadmap

### Phase 1: Foundation
1. **Initialize Wails Project:** Create `src/ui-native` using standard Wails template.
2. **Backend Connection:** Implement a Go service within the UI app to connect to the Firewall Engine via gRPC.
3. **Basic Layout:** Create the shell (Sidebar, Header, Main Content Area) using a lightweight CSS framework (e.g., Tailwind or specialized Windows UI CSS).

### Phase 2: Core Dashboard
1. **Live Traffic Graph:** Use a high-performance canvas library to render traffic stats streaming from `NIC Management`.
2. **Status Panel:** Display health status of all 7 microservices.

### Phase 3: Firewall Management
1. **Rule Editor:** A data-grid view to list, sort, filter, and edit firewall rules.
2. **Object Manager:** UI for managing IP Lists, Port Groups, and Domain Lists.
3. **Logs View:** A virtualized list view to handle high-volume log scrolling.

### Phase 4: Device & Threat Map
1. **Device List:** Grid view of devices from `DHCP Monitor`.
2. **Threat Map:** (Optional) Visual map or list of blocked threats.

### Phase 5: System Integration
1. **Tray Icon:** Right-click menu (Start/Stop Firewall, Panic Mode).
2. **Auto-Start:** Registry integration for boot startup.

---

## 5. Next Steps

To proceed with this plan:
1. Confirm choice of **Wails (Go)**.
2. Initialize the directory `src/ui_native`.
3. Begin Phase 1 implementation.
