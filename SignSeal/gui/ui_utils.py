from __future__ import annotations

import platform
import subprocess
from pathlib import Path

import wx
import wx.svg


def get_svg_bitmap(filename: str, size: tuple[int, int] = (24, 24)) -> wx.Bitmap:
    path = Path(__file__).resolve().parent.parent / "icons" / filename
    if not path.exists():
        return wx.NullBitmap
    try:
        svg = wx.svg.SVGimage.CreateFromFile(str(path))
        return svg.ConvertToScaledBitmap(wx.Size(*size))
    except Exception:
        return wx.NullBitmap


def show_in_explorer(path: Path | None) -> None:
    if path is None:
        return
    target = path.absolute()
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(["explorer", "/select,", str(target)], check=False)
        elif system == "Darwin":
            subprocess.run(["open", "-R", str(target)], check=False)
        else:
            subprocess.run(["xdg-open", str(target.parent)], check=False)
    except Exception:
        pass


class FileDropTarget(wx.FileDropTarget):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def OnDropFiles(self, x, y, filenames):
        del x, y
        if filenames:
            self.callback(filenames[0])
            return True
        return False
