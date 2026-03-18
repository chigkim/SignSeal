from __future__ import annotations

import wx

from ..api import SignSeal

from .key_panel import KeyPanel
from .process_panel import ProcessPanel
from .ui_utils import get_svg_bitmap
from .dialogs import AboutDialog, set_dialog_button_labels
from .vault_dialogs import ask_new_vault, ask_open_vault, prompt_new_password


class WelcomePanel(wx.Panel):
    def __init__(self, parent, on_generate, on_import):
        super().__init__(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)

        sizer.AddStretchSpacer(1)

        desc = wx.StaticText(
            self,
            label="You need at least one key entry to encrypt or decrypt files.\n",
            style=wx.ALIGN_CENTER,
        )
        sizer.Add(desc, 0, wx.ALIGN_CENTER | wx.LEFT | wx.RIGHT | wx.BOTTOM, 30)

        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)

        btn_gen = wx.Button(self, label="Generate Keys", size=(150, 40))
        btn_gen.SetBitmap(get_svg_bitmap("add.svg", (16, 16)))
        btn_gen.Bind(wx.EVT_BUTTON, on_generate)
        btn_sizer.Add(btn_gen, 0, wx.ALL, 10)

        btn_imp = wx.Button(self, label="Import Keys", size=(150, 40))
        btn_imp.SetBitmap(get_svg_bitmap("folder.svg", (16, 16)))
        btn_imp.Bind(wx.EVT_BUTTON, on_import)
        btn_sizer.Add(btn_imp, 0, wx.ALL, 10)

        sizer.Add(btn_sizer, 0, wx.ALIGN_CENTER)
        sizer.AddStretchSpacer(1)

        self.SetSizer(sizer)


class MainFrame(wx.Frame):
    def __init__(self, ss: SignSeal):
        super().__init__(None, title=f"SignSeal - {ss.vault_path}", size=(900, 600))
        self.ss = ss

        self.panel = wx.Panel(self)
        self.status_bar = self.CreateStatusBar()
        self.status_bar.SetStatusText("Ready")

        self.root_sizer = wx.BoxSizer(wx.VERTICAL)

        self.splitter = wx.SplitterWindow(
            self.panel, style=wx.SP_LIVE_UPDATE | wx.SP_3D
        )

        self.right_area = wx.Panel(self.splitter)
        right_sizer = wx.StaticBoxSizer(wx.VERTICAL, self.right_area, "Secure")
        self.panel_process = ProcessPanel(
            right_sizer.GetStaticBox(), self.ss, self.set_status
        )
        right_sizer.Add(self.panel_process, 1, wx.EXPAND)
        self.right_area.SetSizer(right_sizer)

        self.left_area = wx.Panel(self.splitter)
        left_sizer = wx.StaticBoxSizer(wx.VERTICAL, self.left_area, "Keys")
        self.panel_keys = KeyPanel(left_sizer.GetStaticBox(), self.ss, self.refresh_tabs)
        left_sizer.Add(self.panel_keys, 1, wx.EXPAND)
        self.left_area.SetSizer(left_sizer)

        self.splitter.SplitVertically(self.left_area, self.right_area, 300)
        self.splitter.SetMinimumPaneSize(200)

        self.welcome_panel = WelcomePanel(
            self.panel, self.panel_keys.on_generate, self.panel_keys.on_import
        )

        self.root_sizer.Add(self.splitter, 1, wx.EXPAND)
        self.root_sizer.Add(self.welcome_panel, 1, wx.EXPAND)
        self.panel.SetSizer(self.root_sizer)

        self.SetMenuBar(self._build_menu_bar())
        self.Bind(wx.EVT_CLOSE, self.on_close)

        self._check_empty_vault()
        self.Maximize()
        self.Show()

    def _entries(self):
        return self.ss.list()

    def _check_empty_vault(self) -> None:
        if not hasattr(self, "welcome_panel") or not hasattr(self, "splitter"):
            return
        is_empty = not self._entries()
        self.splitter.Show(not is_empty)
        self.welcome_panel.Show(is_empty)
        self.root_sizer.Layout()

    def _build_menu_bar(self) -> wx.MenuBar:
        menu_bar = wx.MenuBar()

        vault_menu = wx.Menu()
        item_new = vault_menu.Append(wx.ID_NEW, "New Vault...")
        item_new.SetBitmap(get_svg_bitmap("add.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.on_new_vault, item_new)

        item_open = vault_menu.Append(wx.ID_OPEN, "Open Vault...")
        item_open.SetBitmap(get_svg_bitmap("folder.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.on_open_vault, item_open)

        vault_menu.AppendSeparator()
        item_change_password = vault_menu.Append(wx.ID_ANY, "Change Vault Password...")
        item_change_password.SetBitmap(get_svg_bitmap("security.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.on_change_password, item_change_password)

        vault_menu.AppendSeparator()
        item_about = vault_menu.Append(wx.ID_ABOUT, "About...")
        self.Bind(wx.EVT_MENU, self.on_about, item_about)

        vault_menu.AppendSeparator()
        exit_item = vault_menu.Append(wx.ID_EXIT)
        self.Bind(wx.EVT_MENU, self.on_exit, exit_item)
        menu_bar.Append(vault_menu, "&Vault")

        keys_menu = wx.Menu()
        item_generate = keys_menu.Append(wx.ID_ANY, "Generate...")
        item_generate.SetBitmap(get_svg_bitmap("add.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_generate, item_generate)

        item_import = keys_menu.Append(wx.ID_ANY, "Import...")
        item_import.SetBitmap(get_svg_bitmap("folder.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_import, item_import)

        keys_menu.AppendSeparator()

        item_export = keys_menu.Append(wx.ID_ANY, "Export...")
        item_export.SetBitmap(get_svg_bitmap("save.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_export, item_export)
        self.Bind(wx.EVT_UPDATE_UI, self.on_update_key_ui, item_export)

        item_rename = keys_menu.Append(wx.ID_ANY, "Rename...")
        item_rename.SetBitmap(get_svg_bitmap("edit.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_rename, item_rename)
        self.Bind(wx.EVT_UPDATE_UI, self.on_update_key_ui, item_rename)

        item_remove = keys_menu.Append(wx.ID_ANY, "Remove...")
        item_remove.SetBitmap(get_svg_bitmap("delete.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_remove, item_remove)
        self.Bind(wx.EVT_UPDATE_UI, self.on_update_key_ui, item_remove)

        keys_menu.AppendSeparator()

        item_note = keys_menu.Append(wx.ID_ANY, "Edit Note...")
        item_note.SetBitmap(get_svg_bitmap("edit.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_edit_note, item_note)
        self.Bind(wx.EVT_UPDATE_UI, self.on_update_key_ui, item_note)

        item_fingerprints = keys_menu.Append(wx.ID_ANY, "Fingerprints...")
        item_fingerprints.SetBitmap(get_svg_bitmap("fingerprint.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_fingerprints, item_fingerprints)
        self.Bind(wx.EVT_UPDATE_UI, self.on_update_key_ui, item_fingerprints)

        keys_menu.AppendSeparator()

        item_paper = keys_menu.Append(wx.ID_ANY, "View Paper Keys...")
        item_paper.SetBitmap(get_svg_bitmap("security.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_paper_keys, item_paper)
        self.Bind(wx.EVT_UPDATE_UI, self.on_update_key_ui, item_paper)

        item_add_paper = keys_menu.Append(wx.ID_ANY, "Add Paper Keys...")
        item_add_paper.SetBitmap(get_svg_bitmap("edit.svg", (16, 16)))
        self.Bind(wx.EVT_MENU, self.panel_keys.on_add_manual, item_add_paper)

        menu_bar.Append(keys_menu, "&Keys")
        return menu_bar

    def on_update_key_ui(self, event) -> None:
        event.Enable(self.panel_keys.has_selection())

    def on_new_vault(self, _event) -> None:
        new_ss = ask_new_vault(self)
        if new_ss:
            self.switch_vault(new_ss)

    def on_open_vault(self, _event) -> None:
        new_ss = ask_open_vault(self)
        if new_ss:
            self.switch_vault(new_ss)

    def switch_vault(self, new_ss: SignSeal) -> None:
        previous_ss = self.ss
        self.ss = new_ss
        self.panel_keys.ss = new_ss
        self.panel_process.ss = new_ss
        self.SetTitle(f"SignSeal - {new_ss.vault_path}")
        self._check_empty_vault()
        self.panel_keys.refresh_lists()
        self.panel_process.refresh_combos()
        if previous_ss is not new_ss:
            previous_ss.close()

    def on_exit(self, _event) -> None:
        self.Close()

    def on_close(self, _event) -> None:
        self.ss.close()
        self.Destroy()

    def on_change_password(self, _event) -> None:
        with wx.PasswordEntryDialog(
            self, "Current vault password:", "Password"
        ) as dialog:
            set_dialog_button_labels(dialog, affirmative="Verify", cancel="Cancel")
            if dialog.ShowModal() != wx.ID_OK:
                return
            if not self.ss.verify_password(dialog.GetValue()):
                wx.MessageBox("Incorrect password.", "Error")
                return

        new_password = prompt_new_password(
            self,
            "Password",
            "New vault password:",
            "Confirm new password:",
        )
        if new_password is None:
            return

        self.ss.password(new_password)
        wx.MessageBox("Success.", "Info")

    def on_about(self, _event) -> None:
        dialog = AboutDialog(self)
        try:
            dialog.ShowModal()
        finally:
            dialog.Destroy()

    def set_status(self, text: str) -> None:
        self.status_bar.SetStatusText(text)

    def refresh_tabs(self) -> None:
        self._check_empty_vault()
        self.panel_process.refresh_combos()
