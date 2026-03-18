from __future__ import annotations

from pathlib import Path

import wx

from ..api import SignSeal
from ..app_services import KeyWorkflowService
from ..key_specs import entry_key_states

from .dialogs import FingerprintDialog, KeySelectionDialog, set_dialog_button_labels
from .ui_utils import show_in_explorer
from .vault_dialogs import CreateVaultDialog


class KeyPanel(wx.Panel):
    def __init__(self, parent, ss: SignSeal, refresh_callback):
        super().__init__(parent)
        self.ss = ss
        self.refresh_callback = refresh_callback
        self.workflow = KeyWorkflowService()
        self.mono_font = wx.Font(
            10,
            wx.FONTFAMILY_TELETYPE,
            wx.FONTSTYLE_NORMAL,
            wx.FONTWEIGHT_NORMAL,
        )

        sizer = wx.BoxSizer(wx.VERTICAL)
        self.list_keys = wx.ListBox(self, style=wx.LB_SINGLE)
        self.list_keys.SetFont(self.mono_font)
        sizer.Add(self.list_keys, 1, wx.EXPAND | wx.ALL, 5)
        self.SetSizer(sizer)
        self.refresh_lists()

    def _entries(self):
        return self.ss.list()

    def has_selection(self) -> bool:
        return self.list_keys.GetSelection() != wx.NOT_FOUND

    def refresh_lists(self) -> None:
        self.list_keys.Clear()
        for summary in self.workflow.describe_entries(self._entries()):
            self.list_keys.Append(summary.format_label(), summary.name)
        self.refresh_callback()

    def _get_selected_name(self) -> str | None:
        selection = self.list_keys.GetSelection()
        return (
            self.list_keys.GetClientData(selection)
            if selection != wx.NOT_FOUND
            else None
        )

    def on_edit_note(self, _event) -> None:
        name = self._get_selected_name()
        if not name:
            return
        current_entry = self._entries().get(name)
        current_note = current_entry.note if current_entry else ""
        dialog = wx.TextEntryDialog(
            self,
            f"Note for '{name}':",
            "Edit Note",
            current_note,
            style=wx.TE_MULTILINE | wx.OK | wx.CANCEL,
        )
        set_dialog_button_labels(dialog, affirmative="Save", cancel="Cancel")
        if dialog.ShowModal() == wx.ID_OK:
            self.ss.note(name, dialog.GetValue())
        dialog.Destroy()

    def on_generate(self, event) -> None:
        with CreateVaultDialog(
            self,
            title="Generate Keys",
            name_label="Display name:",
            default_name="Name",
            create_label="Generate",
        ) as dialog:
            if dialog.ShowModal() != wx.ID_OK:
                return
            name = dialog.entry_name
            password = dialog.password

        if name is None or password is None:
            return

        try:
            self.ss.generate(password, name=name)
            self.refresh_lists()
        except Exception as exc:
            if event is not None:
                wx.MessageBox(str(exc), "Error")

    def on_import(self, event, import_path=None, name=None, selections=None) -> None:
        if not name:
            name = self._get_selected_name()
        if not name:
            if event is None:
                return
            with wx.TextEntryDialog(
                self, "Enter entry name to import into:", "Import Keys"
            ) as dialog:
                set_dialog_button_labels(dialog, affirmative="Continue", cancel="Cancel")
                if dialog.ShowModal() != wx.ID_OK:
                    return
                name = dialog.GetValue()
        if not name:
            return

        if not import_path:
            if event is None:
                return
            with wx.DirDialog(
                self,
                "Select folder containing keys",
                "",
                wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST,
            ) as dialog:
                set_dialog_button_labels(dialog, affirmative="Import", cancel="Cancel")
                if dialog.ShowModal() != wx.ID_OK:
                    return
                import_path = Path(dialog.GetPath())

        try:
            key_states = self.workflow.available_import_selections(import_path)
            if selections is None:
                if event is None:
                    selections = key_states
                else:
                    with KeySelectionDialog(
                        self,
                        "Select Keys to Import",
                        key_states,
                        confirm_label="Import",
                    ) as selection_dialog:
                        if selection_dialog.ShowModal() != wx.ID_OK:
                            return
                        selections = selection_dialog.get_selections()

            final_selection = {
                field_name: bool(selections.get(field_name))
                for field_name in key_states
            }
            if not any(final_selection.values()):
                return

            replacing_labels = self.workflow.overwrite_labels(
                self._entries().get(name),
                final_selection,
            )
            if replacing_labels and event is not None:
                message = f"The following keys already exist in entry '{name}':\n\n"
                message += ", ".join(replacing_labels) + "\n\nOverwrite them?"
                if (
                    wx.MessageBox(
                        message, "Confirm Overwrite", wx.YES_NO | wx.ICON_WARNING
                    )
                    != wx.YES
                ):
                    return

            summary = self.ss.import_keys(name, import_path, selections=final_selection)
            self.refresh_lists()

            if event is not None:
                result = f"Import into '{name}' complete.\n\n"
                if summary.imported_labels:
                    result += f"Imported: {', '.join(summary.imported_labels)}\n"
                if summary.replaced_labels:
                    result += f"Replaced: {', '.join(summary.replaced_labels)}\n"
                wx.MessageBox(result, "Import Result")
        except Exception as exc:
            if event is not None:
                wx.MessageBox(f"Import failed: {exc}", "Error")

    def on_rename(self, _event) -> None:
        old_name = self._get_selected_name()
        if not old_name:
            return
        with wx.TextEntryDialog(
            self, f"New name for '{old_name}':", "Rename", old_name
        ) as dialog:
            set_dialog_button_labels(dialog, affirmative="Rename", cancel="Cancel")
            if dialog.ShowModal() == wx.ID_OK:
                self.ss.rename(old_name, dialog.GetValue())
                self.refresh_lists()

    def on_remove(self, event, selections=None) -> None:
        name = self._get_selected_name()
        if not name:
            return
        entry = self._entries().get(name)
        if entry is None:
            return

        if selections is None:
            with KeySelectionDialog(
                self,
                f"Remove Keys from '{name}'",
                entry_key_states(entry),
                confirm_label="Remove",
            ) as selection_dialog:
                if selection_dialog.ShowModal() != wx.ID_OK:
                    return
                selections = selection_dialog.get_selections()

        if not any(selections.values()):
            return

        summary = self.workflow.remove_plan(entry, selections)
        if not summary.labels:
            return

        if summary.removed_entry:
            if (
                event is not None
                and wx.MessageBox(
                    f"Remove entire entry '{name}' from vault?",
                    "Confirm",
                    wx.YES_NO | wx.ICON_WARNING,
                )
                != wx.YES
            ):
                return
        else:
            if (
                event is not None
                and wx.MessageBox(
                    f"Remove the following keys from '{name}'?\n\n{', '.join(summary.labels)}",
                    "Confirm",
                    wx.YES_NO | wx.ICON_WARNING,
                )
                != wx.YES
            ):
                return

        self.ss.remove_keys(name, selections=selections)
        self.refresh_lists()

    def on_fingerprints(self, event):
        name = self._get_selected_name()
        if not name:
            return None
        try:
            text = self.ss.fingerprint(name)
            if event is not None:
                with FingerprintDialog(self, "Fingerprints", text) as dialog:
                    dialog.ShowModal()
            return text
        except Exception as exc:
            if event is not None:
                wx.MessageBox(str(exc), "Error")
            raise

    def on_export(self, event, target_dir=None, selections=None) -> None:
        name = self._get_selected_name()
        if not name:
            return
        entry = self._entries().get(name)
        if entry is None:
            return

        if selections is None:
            with KeySelectionDialog(
                self,
                f"Export '{name}' Keys",
                entry_key_states(entry),
                confirm_label="Export",
            ) as selection_dialog:
                if selection_dialog.ShowModal() != wx.ID_OK:
                    return
                selections = selection_dialog.get_selections()
        if not any(selections.values()):
            return

        if target_dir is None:
            with wx.DirDialog(
                self, f"Select folder to export '{name}' keys", "", wx.DD_DEFAULT_STYLE
            ) as dialog:
                set_dialog_button_labels(dialog, affirmative="Export", cancel="Cancel")
                if dialog.ShowModal() != wx.ID_OK:
                    return
                target_dir = Path(dialog.GetPath())
        else:
            target_dir = Path(target_dir)

        preview = self.workflow.export_preview(entry, name, target_dir, selections)
        if preview.existing_files and event is not None:
            message = (
                f"The following files already exist in '{preview.target_dir}':\n\n"
            )
            message += ", ".join(preview.existing_files) + "\n\nOverwrite them?"
            if (
                wx.MessageBox(message, "Confirm Overwrite", wx.YES_NO | wx.ICON_WARNING)
                != wx.YES
            ):
                return

        try:
            summary = self.ss.export(name, target_dir, selections=selections)
            if summary.exported_paths and event is not None:
                show_in_explorer(summary.target_dir)
        except Exception as exc:
            if event is not None:
                wx.MessageBox(f"Export failed: {exc}", "Error")

    def on_add_manual(self, event) -> None:
        name = self._get_selected_name()
        if not name:
            with wx.TextEntryDialog(
                self, "Enter entry name for the key:", "Manual Add"
            ) as dialog:
                set_dialog_button_labels(dialog, affirmative="Continue", cancel="Cancel")
                if dialog.ShowModal() != wx.ID_OK:
                    return
                name = dialog.GetValue()
        if not name:
            return

        with wx.TextEntryDialog(
            self,
            f"Enter alphanumeric (paper) key or bundle for '{name}':",
            "Manual Add",
            style=wx.TE_MULTILINE | wx.OK | wx.CANCEL,
        ) as dialog:
            set_dialog_button_labels(dialog, affirmative="Add", cancel="Cancel")
            if dialog.ShowModal() != wx.ID_OK:
                return
            key_text = dialog.GetValue()
        if not key_text:
            return

        try:
            selections = self.workflow.available_import_selections(key_text)
            overwriting = self.workflow.overwrite_labels(
                self._entries().get(name),
                selections,
            )
            if overwriting and event is not None:
                message = f"The following keys already exist for '{name}':\n\n"
                message += ", ".join(overwriting) + "\n\nOverwrite them?"
                if (
                    wx.MessageBox(
                        message, "Confirm Overwrite", wx.YES_NO | wx.ICON_WARNING
                    )
                    != wx.YES
                ):
                    return

            summary = self.ss.add(name, key_text)
            self.refresh_lists()
            if event is not None:
                wx.MessageBox(
                    f"Successfully added {summary.key_count} key(s) to '{name}'.",
                    "Success",
                )
        except Exception as exc:
            if event is not None:
                wx.MessageBox(f"Manual add failed: {exc}", "Error")

    def on_paper_keys(self, event):
        name = self._get_selected_name()
        if not name:
            return None
        text = self.ss.paper_keys(name)
        if event is not None:
            with FingerprintDialog(self, "Paper Keys", text) as dialog:
                dialog.ShowModal()
        return text
