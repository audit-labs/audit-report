"""Enable ``python -m audit_report``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
