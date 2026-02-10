from modules.colors import colorize

# =========================
# Alert Output
# =========================
def alert(level: str, message: str):
    icons = {
        "INFO": "ℹ️",
        "LOW": "✅",
        "MEDIUM": "⚠️",
        "HIGH": "🚨",
        "CORRELATED": "🧠",
    }

    icon = icons.get(level, "")
    text = f"{icon} [{level}] {message}"
    print(colorize(text, level))
    