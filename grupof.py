"""Atajo para el cliente: `python grupof.py --user alice list` (equivale a `python -m src.client.cli`)."""

from src.client.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
