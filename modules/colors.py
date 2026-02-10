# =========================
# ANSI Color Utilities
# =========================

RESET = "\033[0m"

COLORS = {
    "INFO": "\033[36m",      # Cyan
    "LOW": "\033[32m",       # Green
    "MEDIUM": "\033[33m",    # Yellow
    "HIGH": "\033[31m",      # Red
    "CORRELATED": "\033[35m" # Magenta
}

_USE_COLOR = True


def disable_color():
    global _USE_COLOR
    _USE_COLOR = False


def enable_color():
    global _USE_COLOR
    _USE_COLOR = True


def colorize(text: str, level: str) -> str:
    if not _USE_COLOR:
        return text

    color = COLORS.get(level)
    if not color:
        return text

    return f"{color}{text}{RESET}"


