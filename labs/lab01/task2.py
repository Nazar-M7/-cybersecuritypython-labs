users = {
    "risk_manager": {
        "role": "risk_analyst",
        "clearance": 4,
        "department": "Risk Management",
        "active": True,
    },
    "business_analyst": {
        "role": "business_analyst",
        "clearance": 2,
        "department": "Business",
        "active": True,
    },
    "legal_counsel": {
        "role": "legal",
        "clearance": 3,
        "department": "Legal",
        "active": True,
    },
    "contractor_dev": {
        "role": "contractor",
        "clearance": 2,
        "department": "Contract",
        "active": True,
    },
    "obsolete_system": {
        "role": "legacy_system",
        "clearance": 1,
        "department": "Legacy",
        "active": False,
    },
}

resources = [
    ("risk_registers", 4),
    ("business_requirements", 2),
    ("legal_documents", 3),
    ("contract_code", 2),
    ("governance_framework", 4),
    ("meeting_minutes", 1),
    ("regulatory_reports", 3),
    ("executive_dashboards", 4),
    ("project_specs", 2),
    ("public_statements", 1),
]

security_levels = ("Public", "Internal Use", "Restricted", "Highly Restricted")
blocked_users = {"obsolete_system", "contract_expired", "legal_hold"}


def task2():
    for res_name, res_level in resources:
        print(f" {res_name}: {security_levels[res_level - 1]}")

    print("\nрезультати перевірки доступу:")
    user_test = list(users.keys()) + ["unknown_guest"]

    for username in user_test:
        for res_name, res_level in resources:
            if username not in users:
                status = "DENY (User not found)"
            elif username in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[username]["active"]:
                status = "DENY (Account inactive)"
            elif users[username]["clearance"] >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"

            print(f"user={username:<18} resource={res_name:<25} -> {status}")


if __name__ == "__main__":
    task2()
