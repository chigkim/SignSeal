from __future__ import annotations

import wx

from ..exceptions import SignSealError

from .main_frame import MainFrame
from .vault_dialogs import WelcomeDialog


def main() -> None:
    app = wx.App()
    app.SetExitOnFrameDelete(True)

    try:
        ss = None
        with WelcomeDialog() as dialog:
            if dialog.ShowModal() == wx.ID_OK:
                ss = dialog.ss

        if ss:
            MainFrame(ss)
            app.MainLoop()
    except SignSealError as exc:
        wx.MessageBox(str(exc), "Error")
