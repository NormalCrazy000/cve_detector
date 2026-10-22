"""Print an argon2 hash to use as ``CVED_ADMIN_PASSWORD``.

Usage: ``python -m cve_detector.hash_password`` (asks for the password).
Put the result in single quotes in ``.env`` so that ``$`` is not interpreted.
"""

import getpass
import sys

from cve_detector.core.security import hash_password


def main() -> int:
    password = getpass.getpass("Admin password: ")
    if not password:
        print("empty password", file=sys.stderr)
        return 1
    if getpass.getpass("Repeat: ") != password:
        print("passwords do not match", file=sys.stderr)
        return 1
    print(f"CVED_ADMIN_PASSWORD='{hash_password(password)}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
