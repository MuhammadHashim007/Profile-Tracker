import hashlib
import json
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(
    page_title="Browser Fingerprint & Tracker Profiler",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .fingerprint-hash {
        font-family: 'Courier New', Courier, monospace;
        background-color: #1e222b;
        color: #00ff66;
        padding: 12px;
        border-radius: 6px;
        word-break: break-all;
        border-left: 4px solid #00ff66;
        font-size: 1.05rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# JavaScript Telemetry Bridge (Native Query-Param Redirection)
# ---------------------------------------------------------
def inject_client_telemetry_script():
    js_code = """
    <script>
    (function() {
        // Run only once if parameter is missing
        const urlParams = new URLSearchParams(window.parent.location.search);
        if (urlParams.has('fp_data')) return;

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
            language: navigator.language || "en",
            languages: (navigator.languages || []).join(", "),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
            timezoneOffsetMin: new Date().getTimezoneOffset(),
            platform: navigator.platform || "Unknown"
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
                ctx.font = "14px 'Arial', sans-serif";
                ctx.fillStyle = "#f60";
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = "#069";
                ctx.fillText("FingerprintProfiler 🔒", 2, 15);
                ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
                ctx.fillText("FingerprintProfiler 🔒", 4, 17);
                
                const dataUrl = canvas.toDataURL();
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

        const payload = {
            screen: screenData,
            hardware: hardware,
            locale: locale,
            webgl: webglData,
            canvasHash: canvasHash,
            userAgent: navigator.userAgent
        };

        // Write the data into the parent window URL search params to pass into Streamlit
        const currentUrl = new URL(window.parent.location.href);
        currentUrl.searchParams.set("fp_data", encodeURIComponent(JSON.stringify(payload)));
        window.parent.location.href = currentUrl.toString();
    })();
    </script>
    """
    components.html(js_code, height=0)


# ---------------------------------------------------------
# Entropy Weights & Scorer
# ---------------------------------------------------------
ENTROPY_WEIGHTS = {
    "screen_resolution": 4.5,
    "screen_avail_workarea": 3.8,
    "canvas_hash": 8.5,
    "webgl_renderer": 7.2,
    "user_agent": 9.0,
    "timezone_locale": 3.5,
    "hardware_concurrency": 2.2,
    "device_memory": 1.8,
    "touch_support": 1.2,
}

def calculate_profile(raw_data: dict):
    deterministic_payload = json.dumps(raw_data, sort_keys=True)
    master_hash = hashlib.sha256(deterministic_payload.encode("utf-8")).hexdigest()

    total_entropy_bits = sum(ENTROPY_WEIGHTS.values())
    if raw_data.get("canvasHash") in ["Unavailable", "Blocked/Error"]:
        total_entropy_bits -= (ENTROPY_WEIGHTS["canvas_hash"] - 1.0)
    if raw_data.get("webgl", {}).get("renderer") in ["Unavailable", "Blocked/Error", "Generic"]:
        total_entropy_bits -= (ENTROPY_WEIGHTS["webgl_renderer"] - 1.5)

    uniqueness_ratio = 2 ** total_entropy_bits
    return master_hash, total_entropy_bits, uniqueness_ratio


# ---------------------------------------------------------
# UI & Main Logic
# ---------------------------------------------------------
st.title("🛡️ Browser Fingerprint & Tracker Profiler")
st.caption("Inspect non-cookie device telemetry, GPU raster signatures, and hardware entropy.")

with st.sidebar:
    st.header("⚙️ Profiler Controls")
    if st.button("🔄 Re-scan Client Profile"):
        if "fp_data" in st.query_params:
            del st.query_params["fp_data"]
        st.rerun()

    st.markdown("---")
    st.subheader("What is this?")
    st.markdown(
        """
        Web trackers query standard Web APIs (Screen, WebGL, Canvas, Navigator) 
        to compile a persistent **stateless device fingerprint** that tracks you 
        across sessions—even inside **Incognito Mode**.
        """
    )

# Retrieve client data from query parameters
telemetry_param = st.query_params.get("fp_data", None)

if not telemetry_param:
    inject_client_telemetry_script()
    st.info("Reading browser hardware telemetry & graphics pipelines... This will take a second.")
    st.stop()

# Parse the telemetry payload
try:
    telemetry = json.loads(telemetry_param)
except Exception:
    # If the URL parameter was partially truncated or corrupted, clear and retry
    del st.query_params["fp_data"]
    st.rerun()

master_hash, entropy_bits, uniqueness_ratio = calculate_profile(telemetry)

# Key Metrics Row
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
    if uniqueness_ratio > 1_000_000:
        rating, color = "Extremely Unique", "🔴"
    elif uniqueness_ratio > 10_000:
        rating, color = "High Distinctiveness", "🟠"
    else:
        rating, color = "Common Profile", "🟢"

    st.metric(
        label="Uniqueness Tier",
        value=f"{color} {rating}",
        delta=f"~1 in {uniqueness_ratio:,.0f} configs",
        delta_color="inverse",
    )

st.markdown("---")

# Telemetry Signal Details
st.subheader("📋 Detected Subsystem Identifiers")

screen = telemetry.get("screen", {})
hardware = telemetry.get("hardware", {})
locale = telemetry.get("locale", {})
webgl = telemetry.get("webgl", {})

breakdown_data = [
    {"Category": "Graphics / GPU", "Identifier": "WebGL Unmasked Renderer", "Value": str(webgl.get("renderer")), "Entropy Impact": "High (7.2 bits)"},
    {"Category": "Graphics / GPU", "Identifier": "WebGL Unmasked Vendor", "Value": str(webgl.get("vendor")), "Entropy Impact": "Medium (2.0 bits)"},
    {"Category": "Graphics / GPU", "Identifier": "Canvas 2D Hash", "Value": str(telemetry.get("canvasHash")), "Entropy Impact": "Critical (8.5 bits)"},
    {"Category": "Display", "Identifier": "Screen Dimensions", "Value": f"{screen.get('width')}x{screen.get('height')} (Color Depth: {screen.get('colorDepth')} bit)", "Entropy Impact": "Medium (4.5 bits)"},
    {"Category": "Display", "Identifier": "Available Work Area", "Value": f"{screen.get('availWidth')}x{screen.get('availHeight')} (DPI: {screen.get('pixelRatio')})", "Entropy Impact": "Medium (3.8 bits)"},
    {"Category": "Hardware", "Identifier": "Logical CPU Cores", "Value": str(hardware.get("cpuCores")), "Entropy Impact": "Low-Medium (2.2 bits)"},
    {"Category": "Hardware", "Identifier": "RAM Allocation Hint", "Value": f"{hardware.get('deviceMemoryGb')} GB", "Entropy Impact": "Low (1.8 bits)"},
    {"Category": "Hardware", "Identifier": "Max Touch Points", "Value": str(hardware.get("maxTouchPoints")), "Entropy Impact": "Low (1.2 bits)"},
    {"Category": "Localization", "Identifier": "Timezone & Offset", "Value": f"{locale.get('timezone')} (Offset: {locale.get('timezoneOffsetMin')} min)", "Entropy Impact": "Medium (3.5 bits)"},
    {"Category": "Localization", "Identifier": "Primary Language", "Value": f"{locale.get('language')} ({locale.get('languages')})", "Entropy Impact": "Medium (3.0 bits)"},
    {"Category": "Software / OS", "Identifier": "Reported Platform", "Value": str(locale.get("platform")), "Entropy Impact": "Medium (2.5 bits)"},
    {"Category": "Software / OS", "Identifier": "User-Agent Header", "Value": str(telemetry.get("userAgent")), "Entropy Impact": "Critical (9.0 bits)"},
]

df = pd.DataFrame(breakdown_data)
st.dataframe(df, use_container_width=True, hide_index=True)

st.markdown("---")

# Educational Modules
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
        3. **Firefox RFP:** Setting `privacy.resistFingerprinting = true` locks system metrics and standardizes viewport outputs.
        """
    )
