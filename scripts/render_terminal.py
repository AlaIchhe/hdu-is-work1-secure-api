#!/usr/bin/env python3
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
SCREENSHOTS = ROOT / "screenshots"
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def color_for(line):
    if line.startswith("=="):
        return "#58a6ff"
    if line.startswith("COMMAND:") or line.startswith("PS>"):
        return "#d29922"
    if "PASS:" in line:
        return "#3fb950"
    if "FAIL:" in line or "Traceback" in line:
        return "#f85149"
    if line.startswith("HTTP 2"):
        return "#3fb950"
    if line.startswith("HTTP 4") or line.startswith("HTTP 5"):
        return "#f85149"
    if line.startswith("{") or line.startswith("["):
        return "#a5d6ff"
    return "#c9d1d9"


def render(output_name, title, prompt, text):
    if output_name == "06-cve-vulnerable-version.png":
        prompt = "gateway version evidence"
    font = ImageFont.truetype(FONT_PATH, 17)
    bold = ImageFont.truetype(FONT_BOLD_PATH, 17)
    title_font = ImageFont.truetype(FONT_BOLD_PATH, 16)
    width = 1480
    padding = 28
    title_height = 48
    line_height = 24
    wrap_width = 132

    rendered_lines = []
    for raw_line in text.splitlines():
        if not raw_line:
            rendered_lines.append("")
            continue
        parts = textwrap.wrap(
            raw_line,
            width=wrap_width,
            replace_whitespace=False,
            drop_whitespace=False,
        )
        rendered_lines.extend(parts or [""])

    height = title_height + padding * 2 + (len(rendered_lines) + 2) * line_height
    image = Image.new("RGB", (width, height), "#0d1117")
    draw = ImageDraw.Draw(image)

    draw.rectangle((0, 0, width, title_height), fill="#161b22")
    draw.ellipse((18, 16, 32, 30), fill="#ff5f56")
    draw.ellipse((42, 16, 56, 30), fill="#ffbd2e")
    draw.ellipse((66, 16, 80, 30), fill="#27c93f")
    draw.text((100, 14), title, font=title_font, fill="#f0f6fc")

    y = title_height + padding
    draw.text((padding, y), "PS> " + prompt, font=bold, fill="#7ee787")
    y += line_height

    for line in rendered_lines:
        draw.text((padding, y), line, font=font, fill=color_for(line))
        y += line_height

    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    target = SCREENSHOTS / output_name
    image.save(target, "PNG", optimize=True)
    print("Wrote " + str(target) + " (" + str(width) + "x" + str(height) + ")")


def main():
    smoke = (REPORTS / "api-smoke.txt").read_text(encoding="utf-8")
    first, second = smoke.split("== 5. SQL injection login attempt ==", 1)
    render(
        "01-api-auth-and-data.png",
        "Secure API - authentication and protected data",
        "python3 scripts/smoke_test.py",
        first.rstrip(),
    )
    render(
        "02-api-injection-defenses.png",
        "Secure API - SQL injection and XSS defenses",
        "python3 scripts/smoke_test.py",
        "== 5. SQL injection login attempt ==" + second,
    )
    render(
        "03-pytest.png",
        "Automated API tests",
        "python -m pytest",
        (REPORTS / "pytest.txt").read_text(encoding="utf-8"),
    )
    render(
        "04-bandit-sast.png",
        "SAST report - Bandit",
        "bandit -r app.py secure_api -f txt",
        (REPORTS / "bandit.txt").read_text(encoding="utf-8"),
    )
    render(
        "05-pip-audit-sca.png",
        "SCA report - pip-audit",
        "pip-audit -r requirements.txt",
        (REPORTS / "pip-audit.txt").read_text(encoding="utf-8"),
    )
    render(
        "06-cve-vulnerable-version.png",
        "Spring Cloud Gateway versions",
        "curl -I http://127.0.0.1:8080/",
        (REPORTS / "cve-versions.txt").read_text(encoding="utf-8"),
    )
    render(
        "07-cve-reproduction.png",
        "Spring Cloud Gateway SpEL injection",
        "python3 exploit.py http://127.0.0.1:8080",
        (REPORTS / "cve-repro.txt").read_text(encoding="utf-8"),
    )
    render(
        "08-cve-fix-verification.png",
        "Spring Cloud Gateway fixed build verification",
        "python3 verify-fix.py http://127.0.0.1:8081",
        (REPORTS / "cve-fixed.txt").read_text(encoding="utf-8"),
    )


if __name__ == "__main__":
    main()
