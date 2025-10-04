# This file is part of FireFind Project.
#
# Copyright (C) 2025 Your Name
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


from fpdf import FPDF
import matplotlib.pyplot as plt
from datetime import datetime
from PIL import Image, ImageDraw
import os

# Ensure the folder for charts exists
OUTPUT_DIR = "report_charts"
os.makedirs(OUTPUT_DIR, exist_ok=True)

class PDFReport(FPDF):
    def header(self):
        # Draw a border (light green) around the page
        self.set_draw_color(127, 255, 0)
        self.set_line_width(0.6)
        self.rect(5, 5, 200, 287)

        # Title
        self.set_font("Arial", "B", 17)
        self.set_fill_color(144, 238, 144)  # light green header
        self.set_text_color(0)
        self.cell(0, 10, "Firewall Risk Analysis Report - FireFind", ln=True, align="C", fill=True)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def make_circular_logo(self, logo_path, output_name="circular_logo.png"):
        img = Image.open(logo_path).convert("RGBA")
        w, h = img.size
        mask = Image.new("L", (w, h), 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, w, h), fill=255)
        img.putalpha(mask)

        output_path = os.path.join(OUTPUT_DIR, output_name)
        img.save(output_path)
        return output_path

    def add_logos(self, firefind_logo="assets/2.png", triskele_logo="assets/triskele-labs-logo.png", size=45):
        firefind_circ = self.make_circular_logo(firefind_logo, "firefind_circ.png")
        triskele_circ = self.make_circular_logo(triskele_logo, "triskele_circ.png")

        page_width = self.w
        total_width = size * 2 + 10
        x_start = (page_width - total_width) / 2
        y_start = self.get_y()

        self.image(firefind_circ, x=x_start, y=y_start, w=size, h=size)
        self.image(triskele_circ, x=x_start + size + 10, y=y_start, w=size, h=size)

        self.ln(size + 8)

    def add_summary(self, filename, total_rules, total_risks, severity_count, vendor=None):
        self.add_logos()

        self.set_font("Helvetica", "B", 12)
        self.set_text_color(0)
        self.cell(0, 10, "Summary of the Risk Analysis", ln=True, align="C")
        self.ln(2)

        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(200, 200, 200)
        self.cell(70, 8, "Metric", border=1, align="C", fill=True)
        self.cell(120, 8, "Value", border=1, align="C", fill=True)
        self.ln()

        self.set_font("Helvetica", "", 10)

        def row(label, value):
            self.cell(70, 8, label, border=1)
            self.cell(120, 8, str(value), border=1)
            self.ln()

        row("File Analyzed", filename)
        if vendor:
            row("File Belongs to", vendor.title())
        row("Total Rules Analyzed", total_rules)
        row("Total Risks Found", total_risks)

        for level, count in severity_count.items():
            label = "No Risks" if level.upper() == "INFO" else f"{level.title()} Risks"
            row(label, count)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row("Analyzed Date and Time", now)

        self.ln(8)

    def add_charts(self, severity_count, category_count):
        if not severity_count and not category_count:
            return

        severity_colors = {
            "CRITICAL": (1.0, 50/255, 50/255),
            "HIGH": (1.0, 100/255, 0),
            "MEDIUM": (1.0, 200/255, 0),
            "LOW": (180/255, 220/255, 100/255),
            "INFO": (220/255, 220/255, 220/255),
        }

        plt.figure(figsize=(8, 4))

        if severity_count:
            labels, sizes, colors = [], [], []
            for level, count in severity_count.items():
                if count > 0:
                    label = "No Risks" if level.upper() == "INFO" else level.upper()
                    labels.append(label)
                    sizes.append(count)
                    colors.append(severity_colors.get(level.upper(), (0.8, 0.8, 0.8)))

            plt.subplot(1, 2, 1)
            plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
            plt.title("Risks by Severity", fontsize=12, fontweight="bold", pad=20)

        if category_count:
            labels2, sizes2 = [], []
            for cat, count in category_count.items():
                if count > 0:
                    labels2.append(cat)
                    sizes2.append(count)

            plt.subplot(1, 2, 2)
            plt.pie(sizes2, labels=labels2, autopct="%1.1f%%", startangle=140)
            plt.title("Risks by Category", fontsize=12, fontweight="bold", pad=20)

        plt.tight_layout()

        chart_path = os.path.join(OUTPUT_DIR, "charts_combined.png")
        plt.savefig(chart_path, dpi=150)
        plt.close()

        # Place chart image
        x_start = 15
        y_start = self.get_y()
        self.image(chart_path, x=x_start, w=180)

        # Add light green borders around each chart
        self.set_draw_color(19, 80, 41)
        self.set_line_width(0.6)
        self.rect(x_start, y_start, 90, 90)   # severity chart
        self.rect(x_start + 90, y_start, 90, 90)  # category chart

        self.ln(95)

    def add_table(self, findings):
        self.add_page()

        self.set_left_margin(15)
        self.set_right_margin(15)

        self.set_font("Arial", "B", 12)
        self.set_fill_color(200, 200, 200)
        self.set_text_color(0)
        headers = ["Rule ID", "Issue", "Field", "Value", "Severity", "Rule Category"]
        col_widths = [18, 55, 24, 27, 25, 33]

        for i, header in enumerate(headers):
            self.cell(col_widths[i], 10, header, border=1, align="C", fill=True)
        self.ln()

        self.set_font("Helvetica", "", 10)
        severity_colors = {
            "CRITICAL": (255, 50, 50),
            "HIGH": (255, 100, 0),
            "MEDIUM": (255, 200, 0),
            "LOW": (180, 220, 100),
            "INFO": (220, 220, 220),
        }

        for row in findings:
            sev = row.get("severity", "INFO").upper()
            display_sev = "No Risks" if sev == "INFO" else sev
            self.set_fill_color(*severity_colors.get(sev, (255, 255, 255)))
            self.cell(col_widths[0], 8, str(row.get("rule_id", "")), border=0.95, fill=True)
            self.cell(col_widths[1], 8, row.get("issue_type", ""), border=0.95, fill=True)
            self.cell(col_widths[2], 8, row.get("field", ""), border=0.95, fill=True)
            self.cell(col_widths[3], 8, str(row.get("value", "")), border=0.95, fill=True)
            self.cell(col_widths[4], 8, display_sev, border=0.95, fill=True)
            self.cell(col_widths[5], 8, row.get("category", "Uncategorized"), border=0.95, fill=True)
            self.ln()
