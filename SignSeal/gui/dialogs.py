from __future__ import annotations

import wx

from ..config import Config
from ..key_specs import KEY_SPECS

APP_NAME = "SignSeal"
APP_VERSION = "v0.1.0"
APP_CREATED_ON = "2026-03-23"
APP_CREATED_BY = "Chi Kim"
APP_LICENSE = "MIT"
APP_SECURITY_NOTICE = (
    "This software has not undergone formal security auditing. "
    "No guarantee is made regarding the confidentiality, integrity, or availability "
    "of data processed by this software. Use at your own risk."
)
WARNING_COLOR = wx.Colour(192, 0, 0)


def set_dialog_button_labels(
    dialog: wx.Dialog,
    *,
    affirmative: str | None = None,
    cancel: str | None = None,
) -> None:
    find_window_by_id = getattr(dialog, "FindWindowById", None)
    if not callable(find_window_by_id):
        return
    if affirmative is not None:
        ok_button = find_window_by_id(wx.ID_OK, dialog)
        if ok_button is not None:
            ok_button.SetLabel(affirmative)
    if cancel is not None:
        cancel_button = find_window_by_id(wx.ID_CANCEL, dialog)
        if cancel_button is not None:
            cancel_button.SetLabel(cancel)


class AboutDialog(wx.Dialog):
    def __init__(self, parent):
        super().__init__(parent, title=f"About {APP_NAME}", size=(420, 320))

        sizer = wx.BoxSizer(wx.VERTICAL)

        heading = wx.StaticText(self, label=APP_NAME)
        heading.SetFont(
            wx.Font(
                14,
                wx.FONTFAMILY_DEFAULT,
                wx.FONTSTYLE_NORMAL,
                wx.FONTWEIGHT_BOLD,
            )
        )
        sizer.Add(heading, 0, wx.ALIGN_CENTER | wx.TOP | wx.LEFT | wx.RIGHT, 20)

        for line in (
            f"Version: {APP_VERSION}",
            f"Created: {APP_CREATED_ON}",
            f"Created by: {APP_CREATED_BY}",
            f"License: {APP_LICENSE}",
        ):
            sizer.Add(
                wx.StaticText(self, label=line),
                0,
                wx.ALIGN_CENTER | wx.TOP | wx.LEFT | wx.RIGHT,
                10,
            )

        notice = wx.StaticText(self, label=APP_SECURITY_NOTICE, style=wx.ALIGN_CENTER)
        notice.SetForegroundColour(WARNING_COLOR)
        notice.Wrap(360)
        sizer.Add(notice, 0, wx.EXPAND | wx.TOP | wx.LEFT | wx.RIGHT, 15)

        sizer.AddStretchSpacer(1)
        sizer.Add(self.CreateButtonSizer(wx.OK), 0, wx.ALIGN_CENTER | wx.ALL, 15)

        self.SetSizerAndFit(sizer)
        set_dialog_button_labels(self, affirmative="Close")


class FingerprintDialog(wx.Dialog):
    def __init__(self, parent, title: str, text: str):
        super().__init__(parent, title=title, size=(400, 300))
        self.text = text
        self._clipboard_timer: wx.CallLater | None = None

        sizer = wx.BoxSizer(wx.VERTICAL)
        self.text_ctrl = wx.TextCtrl(
            self,
            value=text,
            style=wx.TE_MULTILINE | wx.TE_READONLY,
        )
        sizer.Add(self.text_ctrl, 1, wx.EXPAND | wx.ALL, 10)
        warning = wx.StaticText(self, label=self._clipboard_warning_text())
        warning.Wrap(360)
        sizer.Add(warning, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        copy_button = wx.Button(self, label="Copy to Clipboard")
        copy_button.Bind(wx.EVT_BUTTON, self.on_copy)
        close_button = wx.Button(self, label="Close")
        close_button.Bind(wx.EVT_BUTTON, lambda event: self.EndModal(wx.ID_OK))

        button_sizer.Add(copy_button, 0, wx.RIGHT, 5)
        button_sizer.Add(close_button, 0)
        sizer.Add(button_sizer, 0, wx.ALIGN_RIGHT | wx.ALL, 10)

        self.SetSizer(sizer)

    def on_copy(self, event) -> None:
        if not self._write_clipboard_text(self.text):
            if event is not None:
                wx.MessageBox("Could not access the clipboard.", "Error")
            return
        self._schedule_clipboard_clear()
        if event is not None:
            wx.MessageBox(
                (
                    "Copied to clipboard.\n\n"
                    f"The copied text will be cleared after {Config.CLIPBOARD_CLEAR_MS // 1000} "
                    "seconds if the clipboard still contains the same value."
                ),
                "Sensitive Clipboard Notice",
            )

    def clear_clipboard_if_unchanged(self) -> None:
        if self._read_clipboard_text() == self.text:
            self._clear_clipboard_text()
        self._clipboard_timer = None

    def Destroy(self) -> bool:
        self._stop_clipboard_timer()
        return super().Destroy()

    def _schedule_clipboard_clear(self) -> None:
        self._stop_clipboard_timer()
        self._clipboard_timer = wx.CallLater(
            Config.CLIPBOARD_CLEAR_MS,
            self.clear_clipboard_if_unchanged,
        )

    def _stop_clipboard_timer(self) -> None:
        if self._clipboard_timer is None:
            return
        if self._clipboard_timer.IsRunning():
            self._clipboard_timer.Stop()
        self._clipboard_timer = None

    def _write_clipboard_text(self, value: str) -> bool:
        if not wx.TheClipboard.Open():
            return False
        try:
            wx.TheClipboard.SetData(wx.TextDataObject(value))
            wx.TheClipboard.Flush()
            return True
        finally:
            wx.TheClipboard.Close()

    def _read_clipboard_text(self) -> str | None:
        if not wx.TheClipboard.Open():
            return None
        try:
            data = wx.TextDataObject()
            if not wx.TheClipboard.GetData(data):
                return None
            return data.GetText()
        finally:
            wx.TheClipboard.Close()

    def _clear_clipboard_text(self) -> bool:
        return self._write_clipboard_text("")

    @staticmethod
    def _clipboard_warning_text() -> str:
        return (
            "Clipboard copies are sensitive. SignSeal clears unchanged clipboard text "
            f"after {Config.CLIPBOARD_CLEAR_MS // 1000} seconds."
        )


class KeySelectionDialog(wx.Dialog):
    KEY_LABELS = tuple((spec.field_name, spec.label) for spec in KEY_SPECS)

    def __init__(
        self,
        parent,
        title: str,
        key_states: dict[str, bool],
        *,
        confirm_label: str = "Continue",
    ):
        super().__init__(parent, title=title, size=(320, 250))
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(wx.StaticText(self, label="Select keys to process:"), 0, wx.ALL, 10)

        self.checks = {}
        for key_id, label in self.KEY_LABELS:
            checkbox = wx.CheckBox(self, label=label)
            checkbox.SetValue(False)
            if not key_states.get(key_id, False):
                checkbox.Disable()
            self.checks[key_id] = checkbox
            sizer.Add(checkbox, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        sizer.Add(
            self.CreateButtonSizer(wx.OK | wx.CANCEL), 0, wx.ALIGN_RIGHT | wx.ALL, 10
        )
        self.SetSizer(sizer)
        set_dialog_button_labels(self, affirmative=confirm_label, cancel="Cancel")

    def get_selections(self) -> dict[str, bool]:
        return {
            field_name: checkbox.GetValue()
            for field_name, checkbox in self.checks.items()
        }
