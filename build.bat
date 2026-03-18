if exist __pycache__ rmdir /s /q __pycache__
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist ss-cli.spec del ss-cli.spec
if exist ss-gui.spec del ss-gui.spec
pyinstaller --onefile --console ss-cli.py
pyinstaller --onefile --noconsole --add-data "icons;icons" --name SignSeal ss-gui.py
