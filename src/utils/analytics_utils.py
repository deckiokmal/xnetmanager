import os
import re
import paramiko
import json
import openai
import uuid
from datetime import datetime
from src import db
from src.models.app_models import (
    AIRecommendations,
    BackupData,
    Interface,
    RoutingTable,
    IPAddress,
    DNSSetting,
    DHCPSetting,
    IPRoute,
    FirewallRule,
    SystemSetting,
)


# 1. Tarik Konfigurasi (Backup atau Perangkat Langsung)
def fetch_device_configuration(device_id):
    """Fetch configuration from the latest backup of a device."""
    backup = (
        BackupData.query.filter_by(device_id=device_id)
        .order_by(BackupData.created_at.desc())
        .first()
    )
    if not backup:
        raise ValueError("No backup found for the specified device.")
    with open(backup.backup_path, "r") as file:
        config_data = file.read()
    return config_data


def fetch_live_configuration(device_ip, username, password, port, command):
    """Fetch live configuration from the device using SSH."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(device_ip, username=username, password=password, port=port)
    stdin, stdout, stderr = ssh.exec_command(command)
    config_data = stdout.read().decode()
    ssh.close()
    return config_data


# 2. Parsing dan Validasi
def parse_and_validate_configuration(config_data):
    """Parse and validate configuration data."""
    if "interface" not in config_data:
        raise ValueError("Invalid configuration: Missing interface data.")
    parsed_data = {"interfaces": []}
    for line in config_data.split("\n"):
        if line.startswith("interface"):
            parsed_data["interfaces"].append(line.strip())
    return parsed_data


# 3. Analitik AI
# def analyze_configuration_with_ai(config_data):
#     """Send configuration data to OpenAI API for analysis and recommendations."""
#     response = openai.ChatCompletion.create(
#         model="gpt-4o",  # Pastikan model sesuai
#         messages=[
#             {"role": "system", "content": "You are a network optimization assistant."},
#             {
#                 "role": "user",
#                 "content": f"Analyze this configuration and provide optimization suggestions:\n{config_data}",
#             },
#         ],
#         max_tokens=500,
#     )
#     return response["choices"][0]["message"]["content"].strip()


# 4. Simpan Rekomendasi
# def save_analytics_result(device_id, recommendation_text):
#     """Save AI recommendation to the database."""
#     analytics_result = AIRecommendations(
#         device_id=device_id,
#         recommendation_text=recommendation_text,
#         created_at=datetime.utcnow(),
#     )
#     db.session.add(analytics_result)
#     db.session.commit()
#     return analytics_result


# 5. Terapkan Rekomendasi
def apply_configuration(device_ip, username, password, command):
    """Apply recommended configuration to the device."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(device_ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    ssh.close()
    return output


# 6. Monitoring Perangkat
def monitor_device_status(device_ip):
    """Monitor device status with ping."""
    response = os.system(f"ping -c 1 {device_ip}")
    return "Online" if response == 0 else "Offline"


# 7. Laporkan Aktivitas
def generate_report():
    """Generate a report of analytics and recommendations."""
    reports = AIRecommendations.query.all()
    return [
        {
            "id": r.id,
            "device_id": r.device_id,
            "recommendation": r.recommendation_text,
            "is_applied": r.is_applied,
            "created_at": r.created_at,
        }
        for r in reports
    ]


####################################################################################################
def parse_mikrotik_config(config_text):
    parsed_data = {
        "interfaces": [],
        "routing_tables": [],
        "ip_addresses": [],
        "dns_settings": {},
        "firewall_rules": [],
        "mangle_rules": [],
        "nat_rules": [],
        "services": [],
        "system_settings": {},
        "logging": [],
        "dhcp_settings": [],
        "ip_routes": [],
    }

    # Parse interfaces
    interface_pattern = r"^/interface ethernet set \[ find default-name=([\w-]+) \] .*?disable-running-check=(\w+) .*?name=([\w-]+)"
    parsed_data["interfaces"] = [
        {"default_name": match[0], "disable_running_check": match[1], "name": match[2]}
        for match in re.findall(interface_pattern, config_text, re.MULTILINE)
    ]

    # Parse routing tables
    routing_table_pattern = r"^/routing table add .*?name=([\w-]+)"
    parsed_data["routing_tables"] = re.findall(
        routing_table_pattern, config_text, re.MULTILINE
    )

    # Parse IP addresses
    ip_address_pattern = (
        r"^/ip address add address=([\d./]+) interface=([\w-]+) network=([\d.]+)"
    )
    parsed_data["ip_addresses"] = [
        {"address": match[0], "interface": match[1], "network": match[2]}
        for match in re.findall(ip_address_pattern, config_text, re.MULTILINE)
    ]

    # Parse DNS settings
    dns_pattern = r"^/ip dns set allow-remote-requests=(\w+) servers=([\d.,]+)"
    dns_match = re.search(dns_pattern, config_text, re.MULTILINE)
    if dns_match:
        parsed_data["dns_settings"] = {
            "allow_remote_requests": dns_match.group(1),
            "servers": dns_match.group(2).split(","),
        }

    # Parse DHCP settings
    dhcp_pattern = r"^/ip dhcp-server add address-pool=([\w-]+) interface=([\w-]+) lease-time=([\w:]+)"
    parsed_data["dhcp_settings"] = [
        {"address_pool": match[0], "interface": match[1], "lease_time": match[2]}
        for match in re.findall(dhcp_pattern, config_text, re.MULTILINE)
    ]

    # Parse IP routes
    ip_route_pattern = r"^/ip route add .*?dst-address=([\d./]+) gateway=([\d.]+) .*?routing-table=([\w-]+)"
    parsed_data["ip_routes"] = [
        {"destination": match[0], "gateway": match[1], "routing_table": match[2]}
        for match in re.findall(ip_route_pattern, config_text, re.MULTILINE)
    ]

    # Parse firewall rules
    firewall_pattern = (
        r"^/ip firewall filter add action=(\w+) chain=(\w+) comment=\"([^\"]*)\".*"
    )
    parsed_data["firewall_rules"] = [
        {"action": match[0], "chain": match[1], "comment": match[2]}
        for match in re.findall(firewall_pattern, config_text, re.MULTILINE)
    ]

    # Parse mangle rules
    mangle_pattern = r"^/ip firewall mangle add action=(\w+) chain=(\w+) .*"
    parsed_data["mangle_rules"] = [
        {"action": match[0], "chain": match[1]}
        for match in re.findall(mangle_pattern, config_text, re.MULTILINE)
    ]

    # Parse NAT rules
    nat_pattern = r"^/ip firewall nat add action=(\w+) chain=(\w+) .*"
    parsed_data["nat_rules"] = [
        {"action": match[0], "chain": match[1]}
        for match in re.findall(nat_pattern, config_text, re.MULTILINE)
    ]

    # Parse services
    service_pattern = r"^/ip service set (\w+) port=(\d+)"
    parsed_data["services"] = [
        {"service": match[0], "port": match[1]}
        for match in re.findall(service_pattern, config_text, re.MULTILINE)
    ]

    # Parse system settings
    clock_pattern = r"^/system clock set time-zone-name=([\w/]+)"
    identity_pattern = r"^/system identity set name=\"([^\"]+)\""
    clock_match = re.search(clock_pattern, config_text, re.MULTILINE)
    identity_match = re.search(identity_pattern, config_text, re.MULTILINE)

    if clock_match:
        parsed_data["system_settings"]["time_zone"] = clock_match.group(1)
    if identity_match:
        parsed_data["system_settings"]["identity"] = identity_match.group(1)

    # Parse logging
    logging_pattern = r"^/system logging add topics=([\w,]+)"
    parsed_data["logging"] = re.findall(logging_pattern, config_text, re.MULTILINE)

    return parsed_data


def save_parsing_results(device_id, parsed_data):
    try:
        # Remove existing data for this device to avoid duplication
        Interface.query.filter_by(device_id=device_id).delete()
        RoutingTable.query.filter_by(device_id=device_id).delete()
        IPAddress.query.filter_by(device_id=device_id).delete()
        DNSSetting.query.filter_by(device_id=device_id).delete()
        DHCPSetting.query.filter_by(device_id=device_id).delete()
        IPRoute.query.filter_by(device_id=device_id).delete()
        FirewallRule.query.filter_by(device_id=device_id).delete()
        SystemSetting.query.filter_by(device_id=device_id).delete()

        # Save interfaces
        for interface_data in parsed_data["interfaces"]:
            interface = Interface(
                device_id=device_id,
                name=interface_data["name"],
                default_name=interface_data["default_name"],
                status=interface_data["disable_running_check"],
            )
            db.session.add(interface)

        # Save routing tables
        for table_name in parsed_data["routing_tables"]:
            routing_table = RoutingTable(device_id=device_id, name=table_name)
            db.session.add(routing_table)

        # Save IP addresses
        for ip_data in parsed_data["ip_addresses"]:
            ip_address = IPAddress(
                device_id=device_id,
                address=ip_data["address"],
                interface=ip_data["interface"],
                network=ip_data["network"],
            )
            db.session.add(ip_address)

        # Save DNS settings
        if parsed_data["dns_settings"]:
            dns_setting = DNSSetting(
                device_id=device_id,
                allow_remote_requests=parsed_data["dns_settings"][
                    "allow_remote_requests"
                ]
                == "yes",
                servers=parsed_data["dns_settings"]["servers"],
            )
            db.session.add(dns_setting)

        # Save DHCP settings
        for dhcp_data in parsed_data["dhcp_settings"]:
            dhcp_setting = DHCPSetting(
                device_id=device_id,
                address_pool=dhcp_data["address_pool"],
                interface=dhcp_data["interface"],
                lease_time=dhcp_data["lease_time"],
            )
            db.session.add(dhcp_setting)

        # Save IP routes
        for route_data in parsed_data["ip_routes"]:
            ip_route = IPRoute(
                device_id=device_id,
                destination=route_data["destination"],
                gateway=route_data["gateway"],
                routing_table=route_data["routing_table"],
            )
            db.session.add(ip_route)

        # Save firewall rules
        for rule_data in parsed_data["firewall_rules"]:
            firewall_rule = FirewallRule(
                device_id=device_id,
                action=rule_data["action"],
                chain=rule_data["chain"],
                comment=rule_data.get("comment"),
            )
            db.session.add(firewall_rule)

        # Save system settings
        for key, value in parsed_data["system_settings"].items():
            system_setting = SystemSetting(device_id=device_id, key=key, value=value)
            db.session.add(system_setting)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise RuntimeError(f"Failed to save parsing results: {e}")


def analyze_configuration_with_ai(parsed_data, user_prompt):
    """Analyze configuration data using OpenAI GPT-4 API with user-defined prompt."""
    prompt = f"{user_prompt}\n\n### Configuration Data:\n"
    # for key, value in parsed_data.items():
    #     prompt += f"{key}:{value}\n\n"

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in network security and configuration optimization with enterprise class standard. Provide recommendations in JSON format. Each recommendation should have a 'category' key with readable description and the exact 'configuration_syntax' key. Do not include any additional formatting or text formatting elements in 'configuration_syntax' value.",
                },
                {"role": "user", "content": prompt+", here configuration data:\n"+parsed_data},
            ],
            max_tokens=750,
            temperature=0.7,
        )
        recommendations_text = response["choices"][0]["message"]["content"].strip()
        return json.loads(recommendations_text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse AI response to JSON: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to analyze configuration: {e}")


def save_analytics_results(device_id, analysis_result):
    """Save AI analysis results to the database."""
    try:
        for recommendation in analysis_result:
            ai_recommendation = AIRecommendations(
                id=uuid.uuid4(),  # Generate a unique ID for each recommendation
                device_id=device_id,
                category=recommendation.get("category"),
                configuration_syntax=recommendation.get("configuration_syntax"),
                is_applied=False,  # Default value
                created_at=datetime.utcnow(),  # Default timestamp
            )
            db.session.add(ai_recommendation)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise RuntimeError(f"Failed to save analytics results: {e}")
