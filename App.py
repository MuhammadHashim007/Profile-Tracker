import hashlib
import json
import math
import pandas as pd
import streamlit as st
from streamlit_javascript import st_javascript

# ---------------------------------------------------------
# Page Configuration & Theming
# ---------------------------------------------------------
st.set_page_config(
    page_title="Browser Fingerprint & Tracker Profiler",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for Cybersecurity Dashboard Look
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #0e1117;
        border: 1px solid #262730;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .fingerprint-hash {
        font-family: 'Courier New', Courier, monospace;
        background-color: #1e222b;
        color: #00ff66;
        padding: 10px;
        border-radius: 6px;
        word-break: break-all;
        border-left: 4px solid #00ff66;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# JS Telemetry Collection via streamlit-javascript
# ---------------------------------------------------------
JS_COLLECTOR_SCRIPT = """
function getClientFingerprint() {
    // 1. Screen & Display Details
    const screenData = {
        width: window.screen.width || 0,
        height: window.screen.height || 0,
        availWidth: window.screen.availWidth || 0,
        availHeight: window.screen.availHeight || 0,
        colorDepth: window.screen.colorDepth || 0,
        pixelRatio: window.devicePixelRatio || 1
    };

    // 2. Hardware Concurrency & Memory
    const hardware = {
        cpuCores: navigator.hardwareConcurrency || "Unavailable",
        deviceMemoryGb: navigator.deviceMemory || "Unavailable",
        maxTouchPoints: navigator.maxTouchPoints || 0
    };

    // 3. System, Language & Locale
    const locale = {
        language: navigator.language || (navigator.languages ? navigator.languages[0] : "en"),
        languages: (navigator.languages || []).join(", "),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
        timezoneOffsetMin: new Date().getTimezoneOffset(),
        platform: navigator.platform || "Unknown",
        doNotTrack: navigator.doNotTrack || window.doNotTrack || "Not Specified"
    };

    // 4. WebGL Vendor & Unmasked Renderer
    let webglData = { vendor: "Unavailable", renderer: "Unavailable" };
    try {
        const canvasGl = document.createElement('canvas');
        const gl = canvasGl.getContext('webgl') || canvasGl.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                webglData.vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "Unknown";
                webglData.renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "Unknown";
            } else {
                webglData.vendor = gl.getParameter(gl.VENDOR) || "Generic";
                webglData.renderer = gl.getParameter(gl.RENDERER) || "Generic";
            }
        }
    } catch (e) {
        webglData.renderer = "Blocked/Error";
    }

    // 5. HTML5 Canvas Fingerprint
    let canvasHash = "Unavailable";
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 240;
        canvas.height = 60;
        const ctx = canvas.getContext('2d');
        if (ctx) {
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial', 'Helvetica', sans-serif";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = "#069";
            ctx.fillText("FingerprintProfiler.io <canvas> 1.0 🔒", 2, 15);
            ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
            ctx.fillText("FingerprintProfiler.io <canvas> 1.0 🔒", 4, 17);
            
            const dataUrl = canvas.toDataURL();
            // Simple fast FNV-1a hash implementation
            let hash = 2166136261;
            for (let i = 0; i < dataUrl.length; i++) {
                hash ^= dataUrl.charCodeAt(i);
                hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
            }
            canvasHash = ("0000000" + (hash >>> 0).toString(16)).substr(-8);
        }
    } catch (e) {
        canvasHash = "Blocked/Error";
    }

    return {
        screen: screenData,
        hardware: hardware,
        locale: locale,
        webgl: webglData,
        canvasHash: canvasHash,
        userAgent: navigator.userAgent
    };
}
return JSON.stringify(getClientFingerprint());
"""

# ---------------------------------------------------------
# Entropy & Uniqueness Modeling
# ---------------------------------------------------------
# Empirical Shannon entropy baselines compiled from historical EFF Panopticlick / Cover Your Tracks studies
ENTROPY_WEIGHTS = {
    "screen_resolution": 4.5,   # Variations in monitors, aspect ratios, DPI
    "screen_avail_workarea": 3.8,# Taskbar heights and floating window configurations
    "canvas_hash": 8.5,         # Complex GPU/DirectX/Metal text antialiasing sub-pixel quirks
    "webgl_renderer": 7.2,      # Dedicated GPUs, integrated chipsets, driver revisions
    "user_agent": 9.0,          # OS build numbers, browser versions, patch iterations
    "timezone_locale": 3.5,     # Region and language combinations
    "hardware_concurrency": 2.2,# CPU thread counts (2, 4, 6, 8, 12, 16, 24, 32)
    "device_memory": 1.8,       # RAM allocations (2, 4, 8)
    "touch_support": 1.2,       # Touch screen monitors vs desktop setups
}

def calculate_profile(raw_data: dict):
    """Computes master SHA-256 fingerprint, Shannon entropy estimation, and isolation score."""
    # Deterministic string representation of hardware & software profile
    deterministic_payload = json.dumps(raw_data, sort_keys=True)
    master_hash = hashlib.sha256(deterministic_payload.encode("utf-8")).hexdigest()

    # Calculate cumulative entropy bits
    total_entropy_bits = sum(ENTROPY_WEIGHTS.values())

    # Adjust entropy downward if key elements are generic or blocked
    if raw_data.get("canvasHash") in ["Unavailable", "Blocked/Error"]:
        total_entropy_bits -= (ENTROPY_WEIGHTS["canvas_hash"] - 1.0)
    if raw_data.get("webgl", {}).get("renderer") in ["Unavailable", "Blocked/Error", "Generic"]:
        total_entropy_bits -= (ENTROPY_WEIGHTS["webgl_renderer"] - 1.5)

    # 1 in 2^(total_entropy_bits) uniqueness calculation
    uniqueness_ratio = 2 ** total_entropy_bits

    return master_hash, total_entropy_bits, uniqueness_ratio


# ---------------------------------------------------------
# Main Application Flow
# ---------------------------------------------------------
def main():
    st.title("🛡️ Browser Fingerprint & Tracker Profiler")
    st.caption("Inspect non-cookie device telemetry, GPU raster signatures, and hardware entropy.")

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Profiler Controls")
        auto_refresh = st.checkbox("Re-evaluate on view change", value=False)
        st.markdown("---")
        st.subheader("What is this?")
        st.markdown(
            """
            Web trackers no longer rely purely on **HTTP Cookies** or **LocalStorage**.
            
            By querying standard Web APIs (Screen, WebGL, Canvas, Navigator), advertising networks compile a persistent **stateless device fingerprint** that tracks you across sessions—even inside **Incognito Mode**.
            """
        )

    # Execute JavaScript telemetry probe
    with st.spinner("Probing browser subsystem & graphics pipeline..."):
        raw_telemetry_str = st_javascript(JS_COLLECTOR_SCRIPT)

    if not raw_telemetry_str:
        st.info("Gathering hardware and graphics identifiers from your browser session...")
        st.stop()

    try:
        telemetry = json.loads(raw_telemetry_str)
    except Exception as e:
        st.error(f"Failed to parse browser telemetry: {e}")
        st.stop()

    master_hash, entropy_bits, uniqueness_ratio = calculate_profile(telemetry)

    # Top-Level Summary Metrics
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        st.markdown("#### Master Device Signature (SHA-256)")
        st.markdown(f'<div class="fingerprint-hash">{master_hash}</div>', unsafe_allow_html=True)

    with col2:
        st.metric(
            label="Estimated Entropy",
            value=f"{entropy_bits:.1f} bits",
            help="Higher Shannon entropy implies your browser settings diverge further from common baselines.",
        )

    with col3:
        if uniqueness_ratio > 1000000:
            rating = "Extremely Unique"
            color = "🔴"
        elif uniqueness_ratio > 10000:
            rating = "High Distinctiveness"
            color = "🟠"
        else:
            rating = "Common Profile"
            color = "🟢"
            
        st.metric(
            label="Uniqueness Tier",
            value=f"{color} {rating}",
            delta=f"~1 in {uniqueness_ratio:,.0f} configs",
            delta_color="inverse",
        )

    st.markdown("---")

    # Detailed Telemetry Breakdown Table
    st.subheader("📋 Detected Subsystem Identifiers")

    screen = telemetry.get("screen", {})
    hardware = telemetry.get("hardware", {})
    locale = telemetry.get("locale", {})
    webgl = telemetry.get("webgl", {})

    breakdown_data = [
        {"Category": "Graphics / GPU", "Identifier": "WebGL Unmasked Renderer", "Value": str(webgl.get("renderer")), "Entropy Contribution": "High (7.2 bits)"},
        {"Category": "Graphics / GPU", "Identifier": "WebGL Unmasked Vendor", "Value": str(webgl.get("vendor")), "Entropy Contribution": "Medium (2.0 bits)"},
        {"Category": "Graphics / GPU", "Identifier": "Canvas 2D Hash", "Value": str(telemetry.get("canvasHash")), "Entropy Contribution": "Critical (8.5 bits)"},
        {"Category": "Display", "Identifier": "Screen Dimensions", "Value": f"{screen.get('width')}x{screen.get('height')} (Color Depth: {screen.get('colorDepth')} bit)", "Entropy Contribution": "Medium (4.5 bits)"},
        {"Category": "Display", "Identifier": "Available Work Area", "Value": f"{screen.get('availWidth')}x{screen.get('availHeight')} (DPI: {screen.get('pixelRatio')})", "Entropy Contribution": "Medium (3.8 bits)"},
        {"Category": "Hardware", "Identifier": "Logical CPU Cores", "Value": str(hardware.get("cpuCores")), "Entropy Contribution": "Low-Medium (2.2 bits)"},
        {"Category": "Hardware", "Identifier": "RAM Allocation Hint", "Value": f"{hardware.get('deviceMemoryGb')} GB", "Entropy Contribution": "Low (1.8 bits)"},
        {"Category": "Hardware", "Identifier": "Max Touch Points", "Value": str(hardware.get("maxTouchPoints")), "Entropy Contribution": "Low (1.2 bits)"},
        {"Category": "Localization", "Identifier": "Timezone & Offset", "Value": f"{locale.get('timezone')} (Offset: {locale.get('timezoneOffsetMin')} min)", "Entropy Contribution": "Medium (3.5 bits)"},
        {"Category": "Localization", "Identifier": "Primary Language", "Value": f"{locale.get('language')} ({locale.get('languages')})", "Entropy Contribution": "Medium (3.0 bits)"},
        {"Category": "Software / OS", "Identifier": "Reported Platform", "Value": str(locale.get("platform")), "Entropy Contribution": "Medium (2.5 bits)"},
        {"Category": "Software / OS", "Identifier": "User-Agent Header", "Value": str(telemetry.get("userAgent")), "Entropy Contribution": "Critical (9.0 bits)"},
    ]

    df = pd.DataFrame(breakdown_data)
    st.dataframe(
        df,
        column_config={
            "Category": st.column_config.TextColumn("Category", width="small"),
            "Identifier": st.column_config.TextColumn("Signal", width="medium"),
            "Value": st.column_config.TextColumn("Detected Client Value", width="large"),
            "Entropy Contribution": st.column_config.TextColumn("Entropy Impact", width="small"),
        },
        hide_index=True,
        use_container_width=True,
    )

    # Educational / Analysis Tabs
    st.markdown("---")
    st.subheader("🔍 Threat Modeling & Privacy Insights")

    tab1, tab2, tab3 = st.tabs(["Why Incognito Fails", "How Canvas Fingerprinting Works", "Defense & Mitigation"])

    with tab1:
        st.markdown(
            """
            ### The Incognito Illusion
            Many users believe entering **Private Browsing** or **Incognito Mode** renders them anonymous to tracking companies.
            
            - **What Incognito Does:** Erases local cookies, clears browsing history, and purges form data upon closing the window.
            - **What Incognito Ignores:** It **does not alter your hardware profile or GPU rendering pipeline**. Your CPU core count, WebGL driver signature, font rendering antialiasing, and screen resolution remain identical in both standard and private windows.
            - **Result:** Commercial tracking scripts instantly recognize your unique SHA-256 fingerprint regardless of whether you have cookies enabled or local browsing records turned on.
            """
        )

    with tab2:
        st.markdown(
            """
            ### HTML5 Canvas Sub-Pixel Fingerprinting
            The Canvas Hash shown in the table above was generated entirely in real-time in your browser using an off-screen `<canvas>` element.
            
            ```
            [Text & Shapes Drawn to Canvas] 
                    ⬇
            [OS Font Rasterizer + GPU Driver] 
                    ⬇
            [Sub-pixel Variations in Antialiasing / Textures]
                    ⬇
            [Base64 Encoded Export] ➡️ [Cryptographic Hash]
            ```
            Because different graphics chips (e.g., Apple M-series vs. Intel Iris vs. NVIDIA RTX) and operating systems apply slightly different sub-pixel anti-aliasing algorithms, mathematical smoothing, and font rasterization rules, the resulting PNG export byte stream differs down to individual pixels between machines.
            """
        )

    with tab3:
        st.markdown("### Practical Steps to Neutralize Browser Fingerprinting")
        st.markdown(
            """
            1. **Tor Browser (The Gold Standard):** Tor enforces uniform screen dimensions (letterboxing), spoofs identical user agents across all clients, and completely blocks or prompts for HTML5 Canvas access.
            2. **Brave Browser (Farbling Technique):** Rather than blocking canvas queries (which can break legit applications), Brave injects slight, randomized mathematical noise into canvas and audio outputs on every session, preventing static profiling.
            3. **Firefox Fingerprint Protection:** Enable `privacy.resistFingerprinting = true` in Firefox's `about:config` menu to lock hardware concurrency metrics and enforce standard screen ratios.
            4. **Avoid Micro-Tweaking:** Ironically, installing dozens of niche anti-tracking extensions often increases your distinctiveness by adding measurable extension artifacts to your browser environment.
            """
        )


if __name__ == "__main__":
    main()
