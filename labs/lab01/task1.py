import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT_NUMBER


def main():
    print(f"--- Аналіз паролів (Виконав: {STUDENT_NAME}, Вар: {VARIANT_NUMBER}) ---\n")

    passwords = [
        "APT@Detect10n",
        "simple",
        "Red@Team2023",
        "participant",
        "Blue@T3am",
        "common123",
        "Purple@T34m",
        "regular123",
        "Gr33n@Team",
        "normal123",
    ]

    criteria = {
        "min_length": 7,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }

    forbidden_passwords = {
        "simple",
        "participant",
        "common123",
        "regular123",
        "normal123",
        "test",
    }

    random_indices = random.sample(range(len(passwords)), 3)
    for idx in random_indices:
        passwords.append(passwords[idx])

    # Підготовка до виводу таблиці
    print(f"{'Пароль':<20} | {'Надійність'}")
    print("-" * 35)

    for pwd in passwords:
        has_digit = any(c.isdigit() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)

        criteria_met_count = has_digit + has_upper + has_lower + has_special

        is_unique = passwords.count(pwd) == 1
        min_len = criteria["min_length"]

        if pwd in forbidden_passwords or len(pwd) < min_len:
            status = "Заборонений"
        elif criteria_met_count == 4 and len(pwd) >= (min_len + 4) and is_unique:
            status = "Дуже сильний"
        elif criteria_met_count == 4:
            status = "Сильний"
        elif 0 < criteria_met_count < 4 and len(pwd) >= min_len:
            status = "Середній"
        elif criteria_met_count > 0:
            status = "Слабкий"
        else:
            status = "Невизначений"

        print(f"{pwd:<20} | {status}")


if __name__ == "__main__":
    main()
