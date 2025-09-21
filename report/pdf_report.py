from fpdf import FPDF
import matplotlib.pyplot as plt

class PDFReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(50, 50, 150)  # dark blue header
        self.set_text_color(255)
        self.cell(0, 10, "Firewall Risk Analysis Report - FireFind", ln=True, align="C", fill=True)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def add_summary(self, filename, total_rules, total_risks, severity_count):
        self.set_text_color(0)
        self.set_font("Helvetica", "", 12)
        self.cell(0, 10, f"File Analyzed: {filename}", ln=True)
        self.cell(0, 10, f"Total Rules Analyzed: {total_rules}", ln=True)
        self.cell(0, 10, f"Total Risks Found: {total_risks}", ln=True)
        self.ln(5)

        # Show severity breakdown
        for level, count in severity_count.items():
            label = "No Risks" if level.upper() == "INFO" else level.title()
            self.cell(0, 10, f"{label} Risks: {count}", ln=True)
        self.ln(5)

    def add_severity_chart(self, severity_count, chart_path="severity_chart.png"):
        if not severity_count:
            return  # skip if no data

        # Match table severity colors
        severity_colors = {
            "CRITICAL": (255/255, 50/255, 50/255),
            "HIGH": (255/255, 100/255, 0/255),
            "MEDIUM": (255/255, 200/255, 0/255),
            "LOW": (180/255, 220/255, 100/255),
            "INFO": (220/255, 220/255, 220/255),  # will be labeled "No Risks"
        }

        labels = []
        sizes = []
        colors = []

        for level, count in severity_count.items():
            if count > 0:
                label = "No Risks" if level.upper() == "INFO" else level.upper()
                labels.append(label)
                sizes.append(count)
                colors.append(severity_colors.get(level.upper(), (0.8, 0.8, 0.8)))

        # Create pie chart
        plt.figure(figsize=(4, 4))
        plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
        plt.title("Severity Distribution", fontsize=14, fontweight="bold")
        plt.tight_layout()
        plt.savefig(chart_path, dpi=150)
        plt.close()

        # Insert into PDF with green frame + title
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(0, 100, 0)  # green
        self.cell(0, 10, "Severity Distribution", ln=True, align="C")
        self.ln(2)

        # Frame
        x = 40
        y = self.get_y()
        w = 130
        h = 80
        self.set_draw_color(0, 150, 0)
        self.rect(x, y, w, h)

        # Image inside
        self.image(chart_path, x=x+5, y=y+5, w=w-10, h=h-10)
        self.ln(h + 5)

    def add_table(self, findings):
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(200, 200, 200)
        self.set_text_color(0)
        headers = ["Rule ID", "Issue", "Field", "Value", "Severity"]
        col_widths = [30, 50, 30, 50, 30]

        # Table header
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 10, header, border=1, align="C", fill=True)
        self.ln()

        # Table rows
        self.set_font("Helvetica", "", 10)
        severity_colors = {
            "CRITICAL": (255, 50, 50),
            "HIGH": (255, 100, 0),
            "MEDIUM": (255, 200, 0),
            "LOW": (180, 220, 100),
            "INFO": (220, 220, 220)  # will be shown as "No Risks"
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
