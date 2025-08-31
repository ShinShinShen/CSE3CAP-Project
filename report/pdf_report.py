from fpdf import FPDF

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
        for level, count in severity_count.items():
            self.cell(0, 10, f"{level.title()} Risks: {count}", ln=True)
        self.ln(5)

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
            "INFO": (220, 220, 220)
        }

        for row in findings:
            sev = row.get("severity", "INFO").upper()
            self.set_fill_color(*severity_colors.get(sev, (255, 255, 255)))
            self.cell(col_widths[0], 8, str(row.get("rule_id", "")), border=1, fill=True)
            self.cell(col_widths[1], 8, row.get("issue_type", ""), border=1, fill=True)
            self.cell(col_widths[2], 8, row.get("field", ""), border=1, fill=True)
            self.cell(col_widths[3], 8, str(row.get("value", "")), border=1, fill=True)
            self.cell(col_widths[4], 8, sev, border=1, fill=True)
            self.ln()
