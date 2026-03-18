#!/bin/sh
rm -rf __pycache__
rm -rf build
rm -rf dist
rm -f ss-cli.spec
rm -f ss-gui.spec
pyinstaller --onefile --console ss-cli.py
pyinstaller --add-data="icons:icons" --noconsole --name SignSeal ss-gui.py
