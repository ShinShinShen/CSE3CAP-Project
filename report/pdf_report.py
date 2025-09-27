from fpdf import FPDF
import matplotlib.pyplot as plt
from datetime import datetime
from PIL import Image, ImageDraw

class PDFReport(FPDF):
    def header(self):
        # Draw a border (dark green) around the page
        self.set_draw_color(127, 255, 0)
        self.set_line_width(0.6)
        self.rect(5, 5, 200, 287) 

        # Keep the title or logo here as before
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

    def make_circular_logo(self, logo_path, output_path="circular_logo.png"):
        """Convert logo into a circular PNG"""
        img = Image.open(logo_path).convert("RGBA")
        w, h = img.size
        mask = Image.new("L", (w, h), 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, w, h), fill=255)
        img.putalpha(mask)
        img.save(output_path)
        return output_path

    def add_logos(self, firefind_logo="assets/2.png", triskele_logo="assets/triskele-labs-logo.png", size=45):
        """Place FireFind and Triskele logos side by side centered above summary table"""
        firefind_circ = self.make_circular_logo(firefind_logo, "firefind_circ.png")
        triskele_circ = self.make_circular_logo(triskele_logo, "triskele_circ.png")

        page_width = self.w
        total_width = size * 2 + 10  # two logos + spacing
        x_start = (page_width - total_width) / 2
        y_start = self.get_y()

        self.image(firefind_circ, x=x_start, y=y_start, w=size, h=size)
        self.image(triskele_circ, x=x_start + size + 10, y=y_start, w=size, h=size)

        self.ln(size + 8)

    def add_summary(self, filename, total_rules, total_risks, severity_count, vendor=None):
        # ✅ Add logos above summary
        self.add_logos()

        # ✅ Title
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(0)
        self.cell(0, 10, "Summary of the Risk Analysis", ln=True, align="C")
        self.ln(2)

        # ✅ Table header
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(200, 200, 200)
        self.cell(70, 8, "Metric", border=1, align="C", fill=True)
        self.cell(120, 8, "Value", border=1, align="C", fill=True)
        self.ln()

        # ✅ Table rows
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

        # Add severity breakdown
        for level, count in severity_count.items():
            label = "No Risks" if level.upper() == "INFO" else f"{level.title()} Risks"
            row(label, count)

        # Add analyzed timestamp
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row("Analyzed Date and Time", now)

        self.ln(8)

    def add_severity_chart(self, severity_count, chart_path="severity_chart.png"):
        if not severity_count:
            return

        severity_colors = {
            "CRITICAL": (255/255, 50/255, 50/255),
            "HIGH": (255/255, 100/255, 0/255),
            "MEDIUM": (255/255, 200/255, 0/255),
            "LOW": (180/255, 220/255, 100/255),
            "INFO": (220/255, 220/255, 220/255),
        }

        labels, sizes, colors = [], [], []
        for level, count in severity_count.items():
            if count > 0:
                label = "No Risks" if level.upper() == "INFO" else level.upper()
                labels.append(label)
                sizes.append(count)
                colors.append(severity_colors.get(level.upper(), (0.8, 0.8, 0.8)))

        plt.figure(figsize=(4, 4))
        plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
        plt.title("Severity Distribution", fontsize=14, fontweight="bold")
        plt.tight_layout()
        plt.savefig(chart_path, dpi=150)
        plt.close()

        self.set_font("Helvetica", "B", 12)
        self.set_text_color(0, 100, 0)
        self.cell(0, 10, "Severity Distribution", ln=True, align="C")
        self.ln(2)

        x, y, w, h = 40, self.get_y(), 130, 80
        self.set_draw_color(0, 150, 0)
        self.rect(x, y, w, h)
        self.image(chart_path, x=x+5, y=y+5, w=w-10, h=h-10)
        self.ln(h + 5)

    def add_table(self, findings):
        # ✅ Start main table on new page
        self.add_page()

        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(200, 200, 200)
        self.set_text_color(0)
        headers = ["Rule ID", "Issue", "Field", "Value", "Severity"]
        col_widths = [30, 50, 30, 50, 30]

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
            self.cell(col_widths[0], 8, str(row.get("rule_id", "")), border=1, fill=True)
            self.cell(col_widths[1], 8, row.get("issue_type", ""), border=1, fill=True)
            self.cell(col_widths[2], 8, row.get("field", ""), border=1, fill=True)
            self.cell(col_widths[3], 8, str(row.get("value", "")), border=1, fill=True)
            self.cell(col_widths[4], 8, display_sev, border=1, fill=True)
            self.ln()
