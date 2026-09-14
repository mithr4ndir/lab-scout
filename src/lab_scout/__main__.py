"""Entry point: python -m lab_scout weekly [--dry-run]."""

import sys

from lab_scout.scout import main

if __name__ == "__main__":
    sys.exit(main())
