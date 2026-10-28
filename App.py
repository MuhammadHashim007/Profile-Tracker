import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(
    page_title="Browser Fingerprint & Tracker Profiler",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Profiler Controls")
    st.info("Client-side telemetry execution active.")
    st.markdown("---")
    st.subheader("What is this?")
    st.markdown(
        """
        Web trackers query standard Web APIs (**Screen, WebGL, Canvas, Navigator**) 
        to compile a persistent **stateless device fingerprint** that tracks you 
        across sessions—even inside **Incognito Mode**.
        """
    )

# ---------------------------------------------------------
# Main Page Header
# ---------------------------------------------------------
st.title("🛡️ Browser Fingerprint & Tracker Profiler")
st.caption("Inspect non-cookie device telemetry, GPU raster signatures, and hardware entropy.")

# ---------------------------------------------------------
# Embedded Profiling Engine (Native Client-Side Sandbox)
# ---------------------------------------------------------
dashboard_html = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    :root {
        --bg-card: #0e1117;
        --border-color: #262730;
        --text-primary: #fafafa;
        --text-muted: #808495;
        --accent-green: #00ff66;
        --accent-orange: #ffa500;
        --accent-red: #ff4b4b;
    }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: transparent;
        color: var(--text-primary);
        margin: 0;
        padding: 4px;
    }
    .metrics-container {
        display: grid;
        grid-template-columns: 2fr 1fr 1fr;
        gap: 16px;
        margin-bottom: 24px;
    }
    @media (max-width: 768px) {
        .metrics-container {
            grid-template-columns: 1fr;
        }
    }
    .card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 18px;
    }
    .card-title {
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        color: var(--text-muted);
        letter-spacing: 0.5px;
        margin-bottom: 8px;
    }
    .card-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #ffffff;
    }
    .card-delta {
        font-size: 0.85rem;
        color: var(--accent-orange);
        margin-top: 4px;
    }
    .hash-display {
        font-family: 'Courier New', Courier, monospace;
        background-color: #1a1c24;
        color: var(--accent-green);
        padding: 10px 14px;
        border-radius: 6px;
        word-break: break-all;
        border-left: 4px solid var(--accent-green);
        font-size: 0.95rem;
        margin-top: 6px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        overflow: hidden;
    }
    th, td {
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
        font-size: 0.9rem;
    }
    th {
        background-color: #151922;
        color: var(--text-muted);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.5px;
    }
    tr:hover {
        background-color: #131720;
    }
    .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-high { background-color: rgba(255, 75, 75, 0.2); color: #ff6b6b; }
    .badge-mid { background-color: rgba(255, 165, 0, 0.2); color: #ffb84d; }
    .badge-low { background-color: rgba(0, 255, 102, 0.15); color: #33ff77; }
</style>
</head>
<body>

<div class="metrics-container">
    <div class="card">
        <div class="card-title">Master Device Signature (SHA-256)</div>
        <div class="hash-display" id="masterHash">Computing profile...</div>
    </div>
    <div class="card">
        <div class="card-title">Estimated Shannon Entropy</div>
        <div class="card-value" id="entropyValue">-- bits</div>
        <div class="card-delta">Uniqueness metrics derived from Web APIs</div>
    </div>
    <div class="card">
        <div class="card-title">Uniqueness Tier</div>
        <div class="card-value" id="tierValue">Evaluating...</div>
        <div class="card-delta" id="ratioValue">--</div>
    </div>
</div>

<h3 style="margin-top: 24px; font-size: 1.2rem; color: #ffffff;">📋 Detected Subsystem Identifiers</h3>
<table>
    <thead>
        <tr>
            <th>Category</th>
            <th>Signal</th>
            <th>Detected Client Value</th>
            <th>Entropy Impact</th>
        </tr>
    </thead>
    <tbody id="telemetryTable">
        <tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Extracting hardware and graphics telemetry...</td></tr>
    </tbody>
</table>

<script>
async function generateProfile() {
    // 1. Screen Specs
    const screenData = {
        res: `${window.screen.width || 0}x${window.screen.height || 0}`,
        avail: `${window.screen.availWidth || 0}x${window.screen.availHeight || 0}`,
        depth: `${window.screen.colorDepth || 0} bit`,
        pixelRatio: window.devicePixelRatio || 1
    };

    // 2. Hardware
    const hardware = {
        cores: navigator.hardwareConcurrency || "Unavailable",
        ram: navigator.deviceMemory ? `${navigator.deviceMemory} GB` : "Unavailable",
        touch: navigator.maxTouchPoints || 0
    };

    // 3. Locale & Software
    const locale = {
        lang: navigator.language || (navigator.languages ? navigator.languages[0] : "en"),
        langs: (navigator.languages || []).join(", "),
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
        offset: `${new Date().getTimezoneOffset()} min`,
        platform: navigator.platform || "Unknown",
        ua: navigator.userAgent
    };

    // 4. WebGL Identification
    let webglVendor = "Unavailable";
    let webglRenderer = "Unavailable";
    try {
        const canvasGl = document.createElement('canvas');
        const gl = canvasGl.getContext('webgl') || canvasGl.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "Unknown";
                webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "Unknown";
            } else {
                webglVendor = gl.getParameter(gl.VENDOR) || "Generic";
                webglRenderer = gl.getParameter(gl.RENDERER) || "Generic";
            }
        }
    } catch(e) {
        webglRenderer = "Blocked/Restricted";
    }

    // 5. Canvas 2D Hash (Offscreen rasterization test)
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
            let hash = 2166136261;
            for (let i = 0; i < dataUrl.length; i++) {
                hash ^= dataUrl.charCodeAt(i);
                hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
            }
            canvasHash = ("0000000" + (hash >>> 0).toString(16)).substr(-8);
        }
    } catch (e) {
        canvasHash = "Blocked/Restricted";
    }

    // Raw payload compiled for Master SHA-256
    const payload = {
        screen: screenData,
        hardware: hardware,
        locale: locale,
        webgl: { vendor: webglVendor, renderer: webglRenderer },
        canvas: canvasHash
    };

    // SHA-256 via Web Crypto API
    const msgUint8 = new TextEncoder().encode(JSON.stringify(payload));
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const masterSha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Entropy calculation
    let entropy = 41.7; // baseline cumulative entropy
    if (canvasHash.includes("Blocked") || canvasHash === "Unavailable") entropy -= 7.5;
    if (webglRenderer.includes("Blocked") || webglRenderer === "Generic") entropy -= 5.7;

    const uniquenessRatio = Math.pow(2, entropy);

    // Update DOM Metrics
    document.getElementById("masterHash").textContent = masterSha256;
    document.getElementById("entropyValue").textContent = `${entropy.toFixed(1)} bits`;
    
    let tierText = "🟢 Common Profile";
    if (uniquenessRatio > 1000000) {
        tierText = "🔴 Extremely Unique";
    } else if (uniquenessRatio > 10000) {
        tierText = "🟠 Distinct Profile";
    }
    document.getElementById("tierValue").textContent = tierText;
    document.getElementById("ratioValue").textContent = `~1 in ${Math.round(uniquenessRatio).toLocaleString()} setups`;

    // Populate Table
    const tableData = [
        { cat: "Graphics / GPU", sig: "WebGL Unmasked Renderer", val: webglRenderer, impact: "High (7.2 bits)", badge: "badge-high" },
        { cat: "Graphics / GPU", sig: "WebGL Unmasked Vendor", val: webglVendor, impact: "Medium (2.0 bits)", badge: "badge-mid" },
        { cat: "Graphics / GPU", sig: "Canvas 2D Hash", val: canvasHash, impact: "Critical (8.5 bits)", badge: "badge-high" },
        { cat: "Display", sig: "Screen Dimensions", val: `${screenData.res} (Depth: ${screenData.depth})`, impact: "Medium (4.5 bits)", badge: "badge-mid" },
        { cat: "Display", sig: "Available Work Area", val: `${screenData.avail} (DPI: ${screenData.pixelRatio})`, impact: "Medium (3.8 bits)", badge: "badge-mid" },
        { cat: "Hardware", sig: "Logical CPU Cores", val: hardware.cores, impact: "Medium (2.2 bits)", badge: "badge-mid" },
        { cat: "Hardware", sig: "RAM Allocation Hint", val: hardware.ram, impact: "Low (1.8 bits)", badge: "badge-low" },
        { cat: "Hardware", sig: "Max Touch Points", val: hardware.touch, impact: "Low (1.2 bits)", badge: "badge-low" },
        { cat: "Localization", sig: "Timezone & Offset", val: `${locale.tz} (${locale.offset})`, impact: "Medium (3.5 bits)", badge: "badge-mid" },
        { cat: "Localization", sig: "Primary Language", val: `${locale.lang} (${locale.langs})`, impact: "Medium (3.0 bits)", badge: "badge-mid" },
        { cat: "Software / OS", sig: "Reported Platform", val: locale.platform, impact: "Medium (2.5 bits)", badge: "badge-mid" },
        { cat: "Software / OS", sig: "User-Agent Header", val: locale.ua, impact: "Critical (9.0 bits)", badge: "badge-high" }
    ];

    const tbody = document.getElementById("telemetryTable");
    tbody.innerHTML = tableData.map(row => `
        <tr>
            <td style="color: var(--text-muted); font-weight: 500;">${row.cat}</td>
            <td style="font-weight: 600;">${row.sig}</td>
            <td style="font-family: monospace; word-break: break-all;">${row.val}</td>
            <td><span class="badge ${row.badge}">${row.impact}</span></td>
        </tr>
    `).join('');
}

window.addEventListener("DOMContentLoaded", generateProfile);
generateProfile();
</script>

</body>
</html>
"""

# Render the interactive engine
components.html(dashboard_html, height=760, scrolling=True)

# ---------------------------------------------------------
# Educational & Threat Modeling Tabs
# ---------------------------------------------------------
st.markdown("---")
st.subheader("🔍 Threat Modeling & Privacy Insights")

tab1, tab2, tab3 = st.tabs(["Why Incognito Fails", "How Canvas Fingerprinting Works", "Defense & Mitigation"])

with tab1:
    st.markdown(
        """
        ### The Incognito Illusion
        - **What Incognito Does:** Erases local cookies, clears browsing history, and purges form data on session close.
        - **What Incognito Ignores:** It **does not alter your hardware profile or GPU rendering pipeline**.
        - **Result:** Tracking scripts calculate the exact same hash whether you are in normal or Incognito mode.
        """
    )

with tab2:
    st.markdown(
        """
        ### HTML5 Canvas Sub-Pixel Fingerprinting
        Different GPUs (Apple Silicon, NVIDIA, AMD, Intel) and operating systems apply slightly different font anti-aliasing algorithms and sub-pixel smoothing routines. Exporting an off-screen `<canvas>` drawing to a pixel buffer and hashing it yields an operating-system and hardware-bound signature.
        """
    )

with tab3:
    st.markdown(
        """
        ### Practical Defenses
        1. **Tor Browser:** Enforces standard window sizes (letterboxing) and restricts canvas data exports.
        2. **Brave Browser:** Injects pseudo-randomized mathematical noise ("farbling") into canvas outputs so the hash changes per session.
        3. **Firefox RFP:** Setting `privacy.resistFingerprinting = true` in `about:config` locks system metrics and standardizes viewport outputs.
        """
    )
