/**
 * TARGET 18: CLIENT-SIDE ROUTER & AUTHENTICATION (JavaScript)
 * ===========================================================
 *
 * Vulnerability classes demonstrated:
 * 1. DOM Cross-Site Scripting (DOM XSS) via location.hash parsing
 * 2. Unsafe dynamic code execution (eval) of serialized configuration
 * 3. Hardcoded sensitive client-side credentials
 */

// 1. Hardcoded Secret Key (CWE-798)
const JWT_SECRET_TOKEN = "mutagen_super_secret_client_key_2026_xyz123";

function initializeRouter() {
    // 2. DOM-based XSS (CWE-79)
    // Direct extraction of hash parameter written to innerHTML
    const hash = window.location.hash;
    if (hash && hash.startsWith("#/debug/")) {
        const debugMessage = decodeURIComponent(hash.substring(8));
        const logContainer = document.getElementById("log-output");
        if (logContainer) {
            logContainer.innerHTML = "<b>Debug Message:</b> " + debugMessage;
        }
    }
}

function processSerializedConfig(configString) {
    // 3. Unsafe eval Usage (CWE-95 / Code Injection)
    // Evaluating serialized config objects directly from user-supplied source
    try {
        if (configString && configString.startsWith("config:")) {
            const jsonStr = configString.substring(7);
            const parsedObj = eval("(" + jsonStr + ")");
            console.log("Config loaded:", parsedObj.name);
            return parsedObj;
        }
    } catch (e) {
        console.error("Failed to parse config", e);
    }
    return null;
}

// Initialize on page load
window.addEventListener("DOMContentLoaded", () => {
    initializeRouter();
    
    // Simulate query parsing from URL search params
    const params = new URLSearchParams(window.location.search);
    const userConfig = params.get("config");
    if (userConfig) {
        processSerializedConfig(userConfig);
    }
});
