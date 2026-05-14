"""
eleVADR JSON report generation for NAVV.
"""
import json
import os
from datetime import datetime


def generate_elevadr_report(output_dir, customer_name, rows, inventory, segments):
    """
    Generate an eleVADR-compatible JSON report.
    """
    report_dir = os.path.join(output_dir, "eleVADR")
    os.makedirs(report_dir, exist_ok=True)
    
    report_path = os.path.join(report_dir, f"{customer_name}_elevadr_report.json")
    
    # Heuristic risk mapping
    INSECURE_SERVICES = ["http", "telnet", "ftp", "tftp", "snmp", "vnc", "rlogin"]
    COMMON_SERVICES = ["ssh", "rdp", "smb", "ldap", "dns"]
    
    def get_risk(service):
        s = str(service).lower()
        if any(x in s for x in INSECURE_SERVICES):
            return "High"
        if any(x in s for x in COMMON_SERVICES):
            return "Medium"
        return "Low"

    # 1. Service Panel
    service_data = {}
    for row in rows:
        key = (row.port, row.proto, row.service[0] if isinstance(row.service, tuple) else row.service)
        if key not in service_data:
            service_data[key] = {
                "service": key[2],
                "port": key[0],
                "proto": key[1],
                "risk_level": get_risk(key[2]),
                "count": 0
            }
        service_data[key]["count"] += int(row.count)
    
    service_panel = sorted(service_data.values(), key=lambda x: x["count"], reverse=True)

    # 2. Device Panel
    device_data = {}
    for row in rows:
        # Src Device
        if row.src_ip not in device_data:
            device_data[row.src_ip] = {
                "ip": row.src_ip,
                "hostname": row.src_desc[0],
                "mac": row.src_mac,
                "vendor": "", # Placeholder or extract from mac if possible
                "segment": row.src_desc[2],
                "purdue": row.src_desc[3]
            }
        # Dest Device
        if row.dest_ip not in device_data:
            device_data[row.dest_ip] = {
                "ip": row.dest_ip,
                "hostname": row.dest_desc[0],
                "mac": row.dst_mac,
                "vendor": "",
                "segment": row.dest_desc[2],
                "purdue": row.dest_desc[3]
            }
    
    device_panel = sorted(device_data.values(), key=lambda x: x["ip"])

    # 3. Service Risk Breakdown
    risk_breakdown = {"High": 0, "Medium": 0, "Low": 0}
    for s in service_panel:
        risk_breakdown[s["risk_level"]] += 1

    # 4. OT Cross Segment Lines
    ot_cross_segment = []
    for row in rows:
        s_seg = row.src_desc[2]
        d_seg = row.dest_desc[2]
        if s_seg != d_seg and s_seg != "External" and d_seg != "External":
            ot_cross_segment.append({
                "src_ip": row.src_ip,
                "dst_ip": row.dest_ip,
                "src_segment": s_seg,
                "dst_segment": d_seg,
                "service": row.service[0] if isinstance(row.service, tuple) else row.service,
                "port": row.port,
                "count": int(row.count)
            })

    # Assemble final report
    report = {
        "metadata": {
            "customer": customer_name,
            "generated_at": datetime.now().isoformat(),
            "tool": "NAVV",
            "version": "4.0.0",
            "schema_version": "2.0"
        },
        "service_panel": service_panel,
        "device_panel": device_panel,
        "service_risk_breakdown": risk_breakdown,
        "ot_cross_segment_lines": ot_cross_segment[:1000], # Cap for performance
        "ot_devices": [d for d in device_panel if "External" not in d["segment"]]
    }
    
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
    
    return report_path
