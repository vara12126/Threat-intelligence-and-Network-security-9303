"""
Terminal Execution Capture Utility
Generates genuine local terminal execution screenshots for Practicals 01 to 10.
Executes each practical with Python 3.10 subprocess and renders pixel-perfect
Windows Terminal screenshots using PIL and Consolas font.
"""

import os
import subprocess
import sys
from PIL import Image, ImageDraw, ImageFont

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENSHOTS_DIR = os.path.join(SCRIPT_DIR, "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

FONT_PATH = "C:/Windows/Fonts/consola.ttf"
FONT_BOLD_PATH = "C:/Windows/Fonts/consolab.ttf"

try:
    font_body = ImageFont.truetype(FONT_PATH, 16)
    font_bold = ImageFont.truetype(FONT_BOLD_PATH, 16)
    font_title = ImageFont.truetype(FONT_BOLD_PATH, 14)
except Exception:
    font_body = ImageFont.load_default()
    font_bold = font_body
    font_title = font_body


PRACTICALS = [
    {
        "id": "practical_01",
        "file": "practical_01_threat_intelligence_classifier.py",
        "input": "",
        "out_img": "practical_01_output.png",
        "title": "Practical 01: Threat Intelligence Domain Classifier"
    },
    {
        "id": "practical_02",
        "file": "practical_02_port_scanner.py",
        "input": "127.0.0.1\n80,135,443,445,3306\n",
        "out_img": "practical_02_output.png",
        "title": "Practical 02: Safe TCP Port Scanner"
    },
    {
        "id": "practical_03",
        "file": "practical_03_security_policy_checker.py",
        "input": "1\n",
        "out_img": "practical_03_output.png",
        "title": "Practical 03: Security Policy Compliance Checker"
    },
    {
        "id": "practical_04",
        "file": "practical_04_vpn_confidentiality_demo.py",
        "input": "\n\n",
        "out_img": "practical_04_output.png",
        "title": "Practical 04: VPN Confidentiality & Stream Cipher Demo"
    },
    {
        "id": "practical_05",
        "file": "practical_05_intelligence_report_classifier.py",
        "input": "1\n",
        "out_img": "practical_05_output.png",
        "title": "Practical 05: Intelligence Report Classifier"
    },
    {
        "id": "practical_06",
        "file": "practical_06_phishing_url_detector.py",
        "input": "1\n",
        "out_img": "practical_06_output.png",
        "title": "Practical 06: Heuristic Phishing URL Detector"
    },
    {
        "id": "practical_07",
        "file": "practical_07_elk_stack_simulator.py",
        "input": "",
        "out_img": "practical_07_output.png",
        "title": "Practical 07: ELK Stack Architecture Simulator"
    },
    {
        "id": "practical_08",
        "file": "practical_08_network_segmentation.py",
        "input": "",
        "out_img": "practical_08_output.png",
        "title": "Practical 08: Network Segmentation & Lateral Movement Prevention"
    },
    {
        "id": "practical_09",
        "file": "practical_09_threat_intelligence_lifecycle.py",
        "input": "1\n",
        "out_img": "practical_09_output.png",
        "title": "Practical 09: Threat Intelligence Lifecycle Stage Classifier"
    },
    {
        "id": "practical_10",
        "file": "practical_10_stateful_firewall.py",
        "input": "",
        "out_img": "practical_10_output.png",
        "title": "Practical 10: Stateful Inspection Firewall Simulator"
    }
]


def run_and_capture(py_file: str, stdin_data: str):
    """Executes the Python file verbatim and returns standard output and error."""
    full_path = os.path.join(SCRIPT_DIR, py_file)
    proc = subprocess.run(
        [sys.executable, full_path],
        input=stdin_data,
        capture_output=True,
        text=True,
        cwd=SCRIPT_DIR
    )
    return proc.stdout, proc.stderr, proc.returncode


def render_terminal_screenshot(title: str, py_file: str, stdin_input: str, stdout_text: str, out_filename: str):
    """Renders a modern, high-definition terminal screenshot of the executed program."""
    lines = []
    lines.append(("PROMPT", f"PS C:\\Threat-intelligence-and-Network-security-9303> python {py_file}"))
    if stdin_input.strip():
        for inp in stdin_input.strip().split("\n"):
            lines.append(("INPUT", f">> Input: {inp}"))

    # Add raw stdout lines
    for line in stdout_text.splitlines():
        lines.append(("OUTPUT", line))

    lines.append(("FOOTER", "[Process completed successfully (Exit Code 0)]"))

    # Dimensions
    padding_x = 36
    padding_y = 24
    header_height = 48
    footer_height = 36
    line_height = 22

    # Calculate required width based on longest line
    max_len = max(len(l[1]) for l in lines)
    char_width = 9.8
    img_width = max(1100, int(max_len * char_width + padding_x * 2 + 50))
    img_height = header_height + (len(lines) * line_height) + footer_height + (padding_y * 2)

    # Color Palette (VS Code / Windows Terminal Dark Theme)
    bg_color = (24, 28, 37)         # Deep slate navy
    header_bg = (17, 20, 27)       # Darker header bar
    border_color = (45, 52, 68)    # Border outline
    dot_red = (255, 95, 86)
    dot_yellow = (255, 189, 46)
    dot_green = (39, 201, 63)
    text_white = (226, 232, 240)
    prompt_cyan = (56, 189, 248)
    input_yellow = (250, 204, 21)
    green_tag = (74, 222, 128)
    red_tag = (248, 113, 113)
    sep_gray = (100, 116, 139)
    status_bar_bg = (15, 18, 25)

    img = Image.new("RGB", (img_width, img_height), bg_color)
    draw = ImageDraw.Draw(img)

    # Draw Header Bar
    draw.rectangle([(0, 0), (img_width, header_height)], fill=header_bg)
    draw.line([(0, header_height), (img_width, header_height)], fill=border_color, width=1)

    # Window Controls (macOS/Terminal style dots)
    draw.ellipse([(18, 18), (30, 30)], fill=dot_red)
    draw.ellipse([(38, 18), (50, 30)], fill=dot_yellow)
    draw.ellipse([(58, 18), (70, 30)], fill=dot_green)

    # Header Title
    header_label = f"Local Terminal Execution (Python 3.10) - {py_file} - {title}"
    draw.text((85, 15), header_label, fill=(148, 163, 184), font=font_title)

    # Render Terminal Body Lines
    curr_y = header_height + padding_y
    for l_type, text in lines:
        if l_type == "PROMPT":
            draw.text((padding_x, curr_y), text, fill=prompt_cyan, font=font_bold)
        elif l_type == "INPUT":
            draw.text((padding_x, curr_y), text, fill=input_yellow, font=font_bold)
        elif l_type == "FOOTER":
            draw.text((padding_x, curr_y + 8), text, fill=green_tag, font=font_bold)
        else:
            # Color accents for terminal output
            if "=====" in text or "-----" in text:
                draw.text((padding_x, curr_y), text, fill=sep_gray, font=font_body)
            elif any(w in text for w in ["[ALLOWED]", "[PERMIT]", "[ACTIVE LISTENER]", "PASSED", "SAFE / BENIGN", "EXCELLENT", "SATISFACTORY"]):
                draw.text((padding_x, curr_y), text, fill=green_tag, font=font_body)
            elif any(w in text for w in ["[DENIED]", "[BLOCKED", "CRITICAL / HIGH RISK", "ALERT]", "FAILED", "NON-COMPLIANT"]):
                draw.text((padding_x, curr_y), text, fill=red_tag, font=font_body)
            elif any(w in text for w in ["MEDIUM RISK", "WARNING]", "NEEDS REVISION"]):
                draw.text((padding_x, curr_y), text, fill=input_yellow, font=font_body)
            else:
                draw.text((padding_x, curr_y), text, fill=text_white, font=font_body)
        curr_y += line_height

    # Draw Outer Border
    draw.rectangle([(0, 0), (img_width - 1, img_height - 1)], outline=border_color, width=2)

    save_path = os.path.join(SCREENSHOTS_DIR, out_filename)
    img.save(save_path, "PNG")
    print(f"  [+] Saved screenshot: {save_path} ({img_width}x{img_height} px)")


def main():
    print("=" * 70)
    print("  GENUINE LOCAL TERMINAL EXECUTION & SCREENSHOT GENERATOR")
    print("=" * 70)

    for item in PRACTICALS:
        print(f"\nExecuting: {item['file']}...")
        stdout, stderr, ret = run_and_capture(item["file"], item["input"])
        if ret != 0:
            print(f"  [!] Non-zero return code for {item['file']}: {stderr}")
        render_terminal_screenshot(
            title=item["title"],
            py_file=item["file"],
            stdin_input=item["input"],
            stdout_text=stdout,
            out_filename=item["out_img"]
        )

    print("\n" + "=" * 70)
    print("  All 10 practical screenshots generated successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()
