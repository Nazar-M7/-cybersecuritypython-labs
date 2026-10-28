import csv
import json
import logging
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


@dataclass
class ArpConflict:
    mac_address: str
    ip_addresses: list[str]


def validate_ip(ip: str) -> bool:
    return bool(IP_PATTERN.match(ip))


def validate_mac(mac: str) -> bool:
    return bool(MAC_PATTERN.match(mac))


def analyze_arp_table(
    file_path: Path,
    log_file: Path | None = None,
    detect_spoofing: bool = False,
    output_json: Path | None = None,
):
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        logger.addHandler(file_handler)

    logger.info(f"[INFO] Parsing ARP table snapshot from {file_path}...")

    mac_to_ips = defaultdict(set)
    valid_entries = 0
    invalid_syntax = 0

    try:
        with open(file_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("IP Address", "").strip()
                mac = row.get("MAC Address", "").strip()
                if validate_ip(ip) and validate_mac(mac):
                    valid_entries += 1
                    mac_to_ips[mac].add(ip)
                else:
                    invalid_syntax += 1
    except FileNotFoundError:
        logger.error(f"File {file_path} not found.")
        return
    except PermissionError:
        logger.error(f"Permission denied for file {file_path}.")
        return
    except csv.Error as e:
        logger.error(f"Error parsing CSV file {file_path}: {e}")
        return
    except Exception as e:  # noqa: BLE001
        logger.error(f"An unexpected error occurred while reading {file_path}: {e}")
        return

    logger.info(f"[INFO] Validated {valid_entries} IP/MAC entries.")
    logger.info("=== Validated Entries Summary ===")
    logger.info(f"Valid IP/MAC Pairs : {valid_entries}")
    logger.info(f"Invalid Syntax     : {invalid_syntax}")

    conflicts = []
    if detect_spoofing:
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                conflicts.append(ArpConflict(mac_address=mac, ip_addresses=sorted(ips)))

        if conflicts:
            logger.warning("=== CRITICAL SECURITY ALERTS: ARP-SPOOFING DETECTED ===")
            for conflict in conflicts:
                logger.warning("[ALERT] MAC Address Duplicate Conflict!")
                logger.warning(
                    f"MAC Address: {conflict.mac_address} associated with MULTIPLE IP addresses:"
                )
                for ip in conflict.ip_addresses:
                    logger.warning(f"  - {ip}")
                logger.warning(
                    "-> POSSIBLE MAN-IN-THE-MIDDLE / ARP-SPOOFING ATTACK IN PROGRESS!"
                )

            if output_json:
                try:
                    with open(output_json, "w", encoding="utf-8") as out_f:
                        json.dump([asdict(c) for c in conflicts], out_f, indent=2)
                    logger.info(f"[INFO] Critical conflict logged to {output_json}")
                except PermissionError:
                    logger.error(f"Permission denied for writing to {output_json}.")
                except OSError as e:
                    logger.error(f"Failed to write output to {output_json}: {e}")
                except Exception as e:  # noqa: BLE001
                    logger.error(
                        f"An unexpected error occurred while writing {output_json}: {e}"
                    )
