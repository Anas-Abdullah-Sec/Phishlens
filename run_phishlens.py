"""Entry point for the standalone Windows build. Double-clicking opens the window."""
import sys

from phishlens.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["gui"]))
