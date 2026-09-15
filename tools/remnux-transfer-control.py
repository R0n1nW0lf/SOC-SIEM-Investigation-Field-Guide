#!/usr/bin/env python3

import os
import subprocess
import tkinter as tk
from tkinter import messagebox

SHARE_NAME = "REMnux-Transfer"
MOUNT_POINT = os.path.expanduser("~/Desktop/REMnux-Transfer")

GREEN_ICON = os.path.expanduser(
    "~/.local/share/icons/remnux-transfer/unmounted.svg"
)
RED_ICON = os.path.expanduser(
    "~/.local/share/icons/remnux-transfer/mounted.svg"
)


def is_mounted():
    """Verify that the exact transfer directory is mounted as vboxsf."""
    try:
        result = subprocess.run(
            ["findmnt", "-n", "-T", MOUNT_POINT, "-o", "TARGET,FSTYPE"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return False

        parts = result.stdout.strip().split()
        if len(parts) < 2:
            return False

        target = os.path.realpath(parts[0])
        expected = os.path.realpath(MOUNT_POINT)
        fstype = parts[1]
        return target == expected and fstype == "vboxsf"
    except Exception:
        return False


def update_folder_icon(mounted):
    """Set the desktop transfer-folder icon to match the verified mount state."""
    icon = RED_ICON if mounted else GREEN_ICON

    if not os.path.exists(icon):
        return

    try:
        subprocess.run(
            [
                "gio",
                "set",
                MOUNT_POINT,
                "metadata::custom-icon",
                "file://" + icon,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def refresh_status():
    mounted = is_mounted()
    update_folder_icon(mounted)

    if mounted:
        status_label.config(text="●  SHARE MOUNTED", fg="#d93025")
        detail_label.config(text="WARNING: Host transfer folder is connected.")
        mount_button.config(state="disabled")
        unmount_button.config(state="normal")
    else:
        status_label.config(text="●  SHARE UNMOUNTED", fg="#35a853")
        detail_label.config(text="SAFE: Host transfer folder is disconnected.")
        mount_button.config(state="normal")
        unmount_button.config(state="disabled")


def mount_share():
    os.makedirs(MOUNT_POINT, exist_ok=True)

    if is_mounted():
        refresh_status()
        return

    result = subprocess.run(
        ["pkexec", "mount", "-t", "vboxsf", SHARE_NAME, MOUNT_POINT]
    )
    refresh_status()

    if result.returncode != 0 and not is_mounted():
        messagebox.showerror(
            "Mount Failed",
            "The VirtualBox shared folder could not be mounted.",
        )


def unmount_share():
    if not is_mounted():
        refresh_status()
        return

    result = subprocess.run(["pkexec", "umount", MOUNT_POINT])
    refresh_status()

    if result.returncode != 0 and is_mounted():
        messagebox.showerror(
            "Unmount Failed",
            "The shared folder could not be unmounted.",
        )


def open_transfer_folder():
    subprocess.Popen(
        ["xdg-open", MOUNT_POINT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def periodic_check():
    refresh_status()
    root.after(2000, periodic_check)


root = tk.Tk()
root.title("REMnux Transfer Control")
root.geometry("520x360")
root.resizable(False, False)

title_label = tk.Label(
    root,
    text="REMnux Transfer Control",
    font=("Sans", 20, "bold"),
)
title_label.pack(pady=(25, 15))

status_label = tk.Label(
    root,
    text="Checking...",
    font=("Sans", 17, "bold"),
)
status_label.pack(pady=10)

detail_label = tk.Label(
    root,
    text="Checking actual VirtualBox shared-folder state...",
    font=("Sans", 10),
)
detail_label.pack(pady=(0, 20))

mount_button = tk.Button(
    root,
    text="MOUNT SHARE",
    width=28,
    height=2,
    command=mount_share,
)
mount_button.pack(pady=5)

unmount_button = tk.Button(
    root,
    text="UNMOUNT SHARE",
    width=28,
    height=2,
    command=unmount_share,
)
unmount_button.pack(pady=5)

open_button = tk.Button(
    root,
    text="OPEN TRANSFER FOLDER",
    width=28,
    command=open_transfer_folder,
)
open_button.pack(pady=5)

path_label = tk.Label(root, text=MOUNT_POINT, font=("Sans", 9))
path_label.pack(pady=(15, 0))

refresh_status()
root.after(2000, periodic_check)
root.mainloop()
