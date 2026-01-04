"""Export formats (CSV, PDF)."""

import csv
import logging
from io import StringIO
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from ssl_tester.models import CheckResult, Severity, Rating

logger = logging.getLogger(__name__)


def export_to_csv(results: List[CheckResult], output_path: Optional[Path] = None) -> str:
    """
    Export check results to CSV format.
    
    Args:
        results: List of CheckResult
        output_path: Optional path to save CSV file
        
    Returns:
        CSV string
    """
    if not results:
        return ""
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Header row
    writer.writerow([
        "Target",
        "Port",
        "Service",
        "Timestamp",
        "Rating",
        "Overall Severity",
        "Chain Valid",
        "Hostname Match",
        "Certificate Valid",
        "Days Until Expiry",
        "Protocol Best",
        "Protocol Deprecated",
        "Cipher Count",
        "Weak Ciphers",
        "PFS Supported",
        "Vulnerabilities Found",
        "HSTS Enabled",
        "OCSP Stapling",
        "TLS Compression",
        "CRL Reachable",
        "OCSP Reachable",
        "Summary",
    ])
    
    # Data rows
    for result in results:
        protocol_best = result.protocol_check.best_version if result.protocol_check else "N/A"
        protocol_deprecated = ", ".join(result.protocol_check.deprecated_versions) if result.protocol_check and result.protocol_check.deprecated_versions else "None"
        cipher_count = len(result.cipher_check.supported_ciphers) if result.cipher_check else 0
        weak_ciphers = ", ".join(result.cipher_check.weak_ciphers) if result.cipher_check and result.cipher_check.weak_ciphers else "None"
        pfs_supported = result.cipher_check.pfs_supported if result.cipher_check else False
        vulnerabilities_found = len([v for v in result.vulnerability_checks if v.vulnerable]) if result.vulnerability_checks else 0
        hsts_enabled = result.security_check.hsts_enabled if result.security_check else False
        ocsp_stapling = result.security_check.ocsp_stapling_enabled if result.security_check else False
        tls_compression = result.security_check.tls_compression_enabled if result.security_check else False
        crl_reachable = all(crl.reachable for crl in result.crl_checks) if result.crl_checks else True
        ocsp_reachable = all(ocsp.reachable for ocsp in result.ocsp_checks) if result.ocsp_checks else True
        
        writer.writerow([
            result.target_host,
            result.target_port,
            result.service_type or "HTTPS",
            result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            result.rating.value if result.rating else "N/A",
            result.overall_severity.value,
            result.chain_check.chain_valid and result.chain_check.trust_store_valid,
            result.hostname_check.matches,
            result.validity_check.is_valid,
            result.validity_check.days_until_expiry,
            protocol_best,
            protocol_deprecated,
            cipher_count,
            weak_ciphers,
            pfs_supported,
            vulnerabilities_found,
            hsts_enabled,
            ocsp_stapling,
            tls_compression,
            crl_reachable,
            ocsp_reachable,
            result.summary.replace("\n", " ").replace("; ", ";"),
        ])
    
    csv_content = output.getvalue()
    output.close()
    
    # Save to file if path provided
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_content)
        logger.info(f"CSV report saved to {output_path}")
    
    return csv_content


def export_to_pdf(results: List[CheckResult], output_path: Path) -> None:
    """
    Export check results to PDF format (optional).
    
    Args:
        results: List of CheckResult
        output_path: Path to save PDF file
        
    Raises:
        ImportError: If reportlab is not installed
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except ImportError:
        raise ImportError(
            "reportlab is required for PDF export. Install it with: pip install reportlab"
        )
    
    doc = SimpleDocTemplate(str(output_path), pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#667eea"),
        spaceAfter=30,
    )
    story.append(Paragraph("SSL/TLS Certificate Check Report", title_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # Summary table
    for result in results:
        # Target info
        story.append(Paragraph(f"<b>Target:</b> {result.target_host}:{result.target_port}", styles["Normal"]))
        if result.service_type:
            story.append(Paragraph(f"<b>Service:</b> {result.service_type}", styles["Normal"]))
        story.append(Paragraph(f"<b>Timestamp:</b> {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Rating:</b> {result.rating.value if result.rating else 'N/A'}", styles["Normal"]))
        story.append(Paragraph(f"<b>Overall Status:</b> {result.overall_severity.value}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))
        
        # Summary
        story.append(Paragraph("<b>Summary:</b>", styles["Heading2"]))
        story.append(Paragraph(result.summary or "All checks passed successfully", styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))
        
        # Certificate info
        story.append(Paragraph("<b>Certificate Information</b>", styles["Heading2"]))
        cert_data = [
            ["Chain Valid", str(result.chain_check.chain_valid and result.chain_check.trust_store_valid)],
            ["Hostname Match", str(result.hostname_check.matches)],
            ["Certificate Valid", str(result.validity_check.is_valid)],
            ["Days Until Expiry", str(result.validity_check.days_until_expiry)],
        ]
        cert_table = Table(cert_data, colWidths=[2 * inch, 4 * inch])
        cert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(cert_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Protocol info
        if result.protocol_check:
            story.append(Paragraph("<b>Protocol Versions</b>", styles["Heading2"]))
            protocol_data = [
                ["Best Version", result.protocol_check.best_version or "N/A"],
                ["Supported Versions", ", ".join(result.protocol_check.supported_versions) if result.protocol_check.supported_versions else "None"],
            ]
            if result.protocol_check.deprecated_versions:
                protocol_data.append(["Deprecated Versions", ", ".join(result.protocol_check.deprecated_versions)])
            protocol_table = Table(protocol_data, colWidths=[2 * inch, 4 * inch])
            protocol_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(protocol_table)
            story.append(Spacer(1, 0.3 * inch))
        
        # Cipher info
        if result.cipher_check:
            story.append(Paragraph("<b>Cipher Suites</b>", styles["Heading2"]))
            cipher_data = [
                ["Supported Ciphers", str(len(result.cipher_check.supported_ciphers))],
                ["PFS Supported", str(result.cipher_check.pfs_supported)],
            ]
            if result.cipher_check.weak_ciphers:
                cipher_data.append(["Weak Ciphers", ", ".join(result.cipher_check.weak_ciphers)])
            cipher_table = Table(cipher_data, colWidths=[2 * inch, 4 * inch])
            cipher_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(cipher_table)
            story.append(Spacer(1, 0.3 * inch))
        
        # Vulnerabilities
        if result.vulnerability_checks:
            vulnerable_count = len([v for v in result.vulnerability_checks if v.vulnerable])
            story.append(Paragraph(f"<b>Cryptographic Vulnerabilities</b>", styles["Heading2"]))
            story.append(Paragraph(f"Vulnerable: {vulnerable_count} of {len(result.vulnerability_checks)}", styles["Normal"]))
            story.append(Spacer(1, 0.3 * inch))
        
        # Security best practices
        if result.security_check:
            story.append(Paragraph("<b>Security Best Practices</b>", styles["Heading2"]))
            security_data = [
                ["HSTS Enabled", str(result.security_check.hsts_enabled)],
                ["OCSP Stapling", str(result.security_check.ocsp_stapling_enabled)],
                ["TLS Compression", str(result.security_check.tls_compression_enabled)],
            ]
            security_table = Table(security_data, colWidths=[2 * inch, 4 * inch])
            security_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(security_table)
            story.append(Spacer(1, 0.3 * inch))
        
        # Page break between results
        if len(results) > 1 and result != results[-1]:
            story.append(Spacer(1, 0.5 * inch))
            story.append(Paragraph("<i>--- Continued on next page ---</i>", styles["Normal"]))
            story.append(Spacer(1, 0.5 * inch))
    
    doc.build(story)
    logger.info(f"PDF report saved to {output_path}")

