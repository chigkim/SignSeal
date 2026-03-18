from __future__ import annotations

import threading

import wx

from ..api import SignSeal
from ..app_services import ProcessWorkflowService
from ..models import ProcessMode

from .dialogs import set_dialog_button_labels
from .ui_utils import FileDropTarget, get_svg_bitmap, show_in_explorer


class ProcessPanel(wx.Panel):
    _NO_SENDER_LABEL = "No sender verification"

    def __init__(self, parent, ss: SignSeal, status_callback):
        super().__init__(parent)
        self.ss = ss
        self.status_callback = status_callback
        self.workflow = ProcessWorkflowService()
        self.selected_path = ""
        self.mode = ProcessMode.ENCRYPT

        main_sizer = wx.BoxSizer(wx.VERTICAL)
        grid = wx.FlexGridSizer(rows=5, cols=2, vgap=15, hgap=10)
        grid.AddGrowableCol(1, 1)

        self.btn_browse = wx.Button(self, label="Browse...")
        self.btn_browse.SetBitmap(get_svg_bitmap("folder.svg", (16, 16)))
        self.btn_browse.Bind(wx.EVT_BUTTON, self.on_browse)
        grid.Add(self.btn_browse, 0, wx.ALIGN_CENTER_VERTICAL)

        self.lbl_path = wx.StaticText(self, label="Choose a file/folder")
        grid.Add(self.lbl_path, 1, wx.ALIGN_CENTER_VERTICAL | wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Recipient:"), 0, wx.ALIGN_CENTER_VERTICAL)
        self.combo_recipient = wx.Choice(self)
        self.combo_recipient.Bind(wx.EVT_CHOICE, self.on_field_change)
        grid.Add(self.combo_recipient, 1, wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Sender:"), 0, wx.ALIGN_CENTER_VERTICAL)
        self.combo_sender = wx.Choice(self)
        self.combo_sender.Bind(wx.EVT_CHOICE, self.on_field_change)
        grid.Add(self.combo_sender, 1, wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Password:"), 0, wx.ALIGN_CENTER_VERTICAL)
        self.password = wx.TextCtrl(self, style=wx.TE_PASSWORD)
        self.password.Bind(wx.EVT_TEXT, self.on_field_change)
        grid.Add(self.password, 1, wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Compression:"), 0, wx.ALIGN_CENTER_VERTICAL)
        self.chk_compress = wx.CheckBox(self, label="Compress Before Encrypting")
        self.chk_compress.SetValue(True)
        grid.Add(self.chk_compress, 1, wx.EXPAND)

        main_sizer.Add(grid, 0, wx.EXPAND | wx.ALL, 20)

        self.btn_action = wx.Button(self, label="Encrypt", size=(120, 40))
        self.btn_action.SetBitmap(get_svg_bitmap("lock.svg", (20, 20)))
        self.btn_action.Bind(wx.EVT_BUTTON, self.on_action)
        self.btn_action.Disable()
        main_sizer.Add(self.btn_action, 0, wx.ALIGN_CENTER | wx.BOTTOM, 20)

        self.SetSizer(main_sizer)
        self.refresh_combos()
        self.SetDropTarget(FileDropTarget(self.set_input_path))

    def on_browse(self, event) -> None:
        menu = wx.Menu()
        file_item = menu.Append(wx.ID_ANY, "Select File...")
        folder_item = menu.Append(wx.ID_ANY, "Select Folder...")
        self.Bind(wx.EVT_MENU, self._on_browse_file, file_item)
        self.Bind(wx.EVT_MENU, self._on_browse_folder, folder_item)
        button = event.GetEventObject()
        self.PopupMenu(menu, button.GetPosition() + (0, button.GetSize().y))
        menu.Destroy()

    def _on_browse_file(self, _event) -> None:
        with wx.FileDialog(
            self,
            "Choose input file",
            "",
            "",
            "*.*",
            wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
        ) as dialog:
            set_dialog_button_labels(dialog, affirmative="Select", cancel="Cancel")
            if dialog.ShowModal() == wx.ID_OK:
                self.set_input_path(dialog.GetPath())

    def _on_browse_folder(self, _event) -> None:
        with wx.DirDialog(
            self,
            "Choose input directory",
            "",
            wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST,
        ) as dialog:
            set_dialog_button_labels(dialog, affirmative="Select", cancel="Cancel")
            if dialog.ShowModal() == wx.ID_OK:
                self.set_input_path(dialog.GetPath())

    def set_input_path(self, path: str) -> None:
        self.selected_path = path
        self.lbl_path.SetLabel(path)
        self.update_mode()
        self.on_field_change(None)

    def on_field_change(self, _event) -> None:
        sender_name = self._selected_sender_name()
        password_required = self.workflow.password_required(self.mode, sender_name)

        if password_required:
            self.password.Enable(True)
        else:
            self.password.Disable()
            if self.password.GetValue():
                self.password.ChangeValue("")

        ready = bool(self.selected_path and self.combo_recipient.GetStringSelection())
        if password_required:
            ready = ready and bool(self.password.GetValue())
        self.btn_action.Enable(ready)

    def refresh_combos(self) -> None:
        recipient_value = self.combo_recipient.GetStringSelection()
        sender_value = self._selected_sender_name()

        self.combo_recipient.Clear()
        self.combo_sender.Clear()
        self.combo_sender.Append(self._NO_SENDER_LABEL)

        entries = self.ss.list()
        for name in self.workflow.recipient_names(entries, self.mode):
            self.combo_recipient.Append(name)
        for name in self.workflow.sender_names(entries, self.mode):
            self.combo_sender.Append(name)

        if not self.combo_recipient.SetStringSelection(recipient_value):
            self.combo_recipient.SetSelection(
                0 if self.combo_recipient.GetCount() else wx.NOT_FOUND
            )
        if sender_value is None:
            self.combo_sender.SetSelection(
                0 if self.combo_sender.GetCount() else wx.NOT_FOUND
            )
        elif not self.combo_sender.SetStringSelection(sender_value):
            self.combo_sender.SetSelection(
                0 if self.combo_sender.GetCount() else wx.NOT_FOUND
            )

    def update_mode(self) -> None:
        self.mode = self.workflow.mode_for_path(self.selected_path)
        if self.mode == ProcessMode.DECRYPT:
            self.btn_action.SetLabel("Decrypt")
            self.btn_action.SetBitmap(get_svg_bitmap("lock_open.svg", (20, 20)))
            self.chk_compress.Disable()
        else:
            self.btn_action.SetLabel("Encrypt")
            self.btn_action.SetBitmap(get_svg_bitmap("lock.svg", (20, 20)))
            self.chk_compress.Enable()
        self.refresh_combos()
        self.Layout()

    def on_action(self, event, replace=None) -> None:
        path = self.selected_path
        recipient_name = self.combo_recipient.GetStringSelection()
        sender_name = self._selected_sender_name()
        password = self.password.GetValue()
        compress = self.chk_compress.GetValue()

        if not path:
            if event is not None:
                wx.MessageBox("Please select a file.", "Error", wx.ICON_ERROR)
            return

        output_path = self.workflow.output_path(path, self.mode)
        final_replace = bool(replace)
        if replace is None and output_path and output_path.exists():
            if event is None:
                return
            if (
                wx.MessageBox(
                    f"Output path already exists:\n{output_path}\n\nReplace it?",
                    "Confirm",
                    wx.YES_NO,
                )
                != wx.YES
            ):
                return
            final_replace = True

        if not self._confirm_unverified_decrypt(path, sender_name, event):
            self.status_callback("Cancelled")
            self.on_field_change(None)
            return

        self.btn_action.Disable()
        self.status_callback(f"{self.mode.capitalize()}ing...")

        def run() -> None:
            try:
                if self.mode == ProcessMode.ENCRYPT:
                    self.ss.encrypt(
                        path,
                        recipient_key=recipient_name,
                        sender_key=sender_name,
                        sender_passphrase=password,
                        replace=final_replace,
                        compress=compress,
                    )
                else:
                    self.ss.decrypt(
                        path,
                        recipient_key=recipient_name,
                        recipient_passphrase=password,
                        sender_key=sender_name,
                        replace=final_replace,
                    )
                produced_path = output_path
                if event is not None:
                    wx.CallAfter(lambda: show_in_explorer(produced_path))
                wx.CallAfter(lambda: self.status_callback("Ready"))
            except Exception as exc:
                error_message = str(exc)
                if event is not None:
                    wx.CallAfter(
                        lambda: wx.MessageBox(error_message, "Error", wx.ICON_ERROR)
                    )
                wx.CallAfter(lambda: self.status_callback("Error"))
            finally:
                wx.CallAfter(lambda: self.password.ChangeValue(""))
                wx.CallAfter(lambda: self.btn_action.Enable())

        threading.Thread(target=run, daemon=True).start()

    def _confirm_unverified_decrypt(
        self,
        path: str,
        sender_name: str | None,
        event,
    ) -> bool:
        warning = self.workflow.unverified_decrypt_warning(path, self.mode, sender_name)
        if warning is None or event is None:
            return True
        return (
            wx.MessageBox(
                warning,
                "Security Warning",
                wx.YES_NO | wx.ICON_WARNING | wx.CENTRE,
            )
            == wx.YES
        )

    def _selected_sender_name(self) -> str | None:
        value = self.combo_sender.GetStringSelection()
        if not value or value == self._NO_SENDER_LABEL:
            return None
        return value
