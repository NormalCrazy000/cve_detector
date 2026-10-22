"""Print the OpenAPI schema (input of the frontend's generated TypeScript client).

Usage: ``python -m cve_detector.export_openapi > ../frontend/openapi.json``
"""

import json

from cve_detector.main import create_app


def main() -> None:
    print(json.dumps(create_app().openapi(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
