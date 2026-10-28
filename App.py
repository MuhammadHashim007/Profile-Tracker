import hashlib
import json
import pandas as pd
import streamlit as st
from streamlit_javascript import st_javascript

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
        font-size: 1.1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

JS_COLLECTOR_SCRIPT = """
(function() {
    try {
        const screenData = {
            width: window.screen.width || 0,
            height: window.screen.height || 0,
            availWidth: window.screen.availWidth || 0,
            availHeight: window.screen.availHeight || 0,
            colorDepth: window.screen.colorDepth || 0,
            pixelRatio: window.devicePixelRatio || 1
        };

        const hardware = {
            cpuCores: navigator.hardwareConcurrency || "Unavailable",
            deviceMemoryGb: navigator.deviceMemory || "Unavailable",
            maxTouchPoints: navigator.maxTouchPoints || 0
        };

        const locale = {
            language: navigator.language || (navigator.languages ? navigator.languages[0] : "en"),
            languages: (navigator.languages || []).join(", "),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
            timezoneOffsetMin: new Date().getTimezoneOffset(),
            platform: navigator.platform || "Unknown",
            doNotTrack: navigator.doNotTrack || window.doNotTrack || "Not Specified"
        };

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
            canvasHash = "Blocked/Error";
        }

        return JSON.stringify({
            screen: screenData,
            hardware: hardware,
            locale: locale,
            webgl: webglData,
            canvasHash: canvasHash,
            userAgent: navigator.userAgent
        });
    } catch(err) {
        return JSON.stringify({ error: err.toString() });
    }
})();
"""

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


def main():
    st.title("🛡️ Browser Fingerprint & Tracker Profiler")
    st.caption("Inspect non-cookie device telemetry, GPU raster signatures, and hardware entropy.")

    with st.sidebar:
        st.header("⚙️ Profiler Controls")
        if st.button("🔄 Force Re-scan"):
            st.session_state.pop("telemetry", None)
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

    if "telemetry" not in st.session_state:
        st.session_state.telemetry = None

    if st.session_state.telemetry is None:
        raw_telemetry_str = st_javascript(JS_COLLECTOR_SCRIPT, key="telemetry_collector")

        if not raw_telemetry_str or raw_telemetry_str == 0:
            st.info("Gathering hardware and graphics identifiers from your browser session...")
            st.caption("Waiting for browser handshake. If this persists, ensure strict ad/script blockers are paused for this domain.")
            return

        try:
            parsed = json.loads(raw_telemetry_str)
            if "error" in parsed:
                st.error(f"JavaScript execution error: {parsed['error']}")
                return
            st.session_state.telemetry = parsed
            st.rerun()
        except Exception as e:
            st.error(f"Failed to parse browser telemetry: {e}")
            return

    telemetry = st.session_state.telemetry
    master_hash, entropy_bits, uniqueness_ratio = calculate_profile(telemetry)

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
    st.subheader("🔍 Threat Modeling & Privacy Insights")
