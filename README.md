# 🛡️ Browser Fingerprint & Tracker Profiler ("Am I Unique?")

A production-ready, client-side cybersecurity audit tool built with **Python** and **Streamlit**. It profiles non-cookie browser telemetry, measures hardware distinctiveness, and generates an estimated Shannon Entropy score for any client visiting the application.

## 🚀 Features

- **Zero External APIs / Zero Cost:** Runs self-contained using browser-native APIs and standard Python libraries.
- **Client-Side Telemetry Collection:**
  - Screen dimensions, color depth, and available taskbar workspace.
  - Hardware concurrency (CPU core count) and approximate RAM allocations.
  - WebGL GPU vendor and unmasked renderer detection (`WEBGL_debug_renderer_info`).
  - Off-screen HTML5 Canvas sub-pixel anti-aliasing fingerprinting.
  - Timezone, locale, and touch-point detection.
- **Entropy & Distinctiveness Modeling:** Calculates Shannon entropy bits ($\sum -P(x)\log_2 P(x)$) and projects config uniqueness against population baselines.
- **Privacy Defense Analysis:** Explains why Private/Incognito modes fail to mask device footprints and evaluates countermeasures (Tor, Brave Farbling, Firefox RFP).

---

## 🛠️ Local Development Setup

### 1. Prerequisites
- Python 3.9+ installed on your machine.

### 2. Installation
Clone the repository and install the dependencies:

```bash
git clone [https://github.com/your-username/browser-fingerprint-profiler.git](https://github.com/your-username/browser-fingerprint-profiler.git)
cd browser-fingerprint-profiler
pip install -r requirements.txt
