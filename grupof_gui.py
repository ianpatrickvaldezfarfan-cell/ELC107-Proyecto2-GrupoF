"""Atajo para la interfaz gráfica: `python grupof_gui.py [--user alice]` (equivale a `python -m src.client.gui`)."""

from src.client.gui import main

if __name__ == "__main__":
    raise SystemExit(main())
