#!/usr/bin/env python3

import os
import subprocess
import tkinter as tk
from tkinter import messagebox

SHARE_NAME = "REMnux-Transfer"
MOUNT_POINT = os.path.expanduser("~/Desktop/REMnux-Transfer")


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
        mountpoint = os.path.realpath(MOUNT_POINT)
        fstype = parts[1]
        return target == mountpoint and fstype == "vboxsf"
    except Exception:
        return False


def refresh_status():
    mounted = is_mounted()
    if mounted:
        status_label.config(text="●  SHARE MOUNTED", fg="green")
        detail_label.config(text="Host transfer folder is connected.")
        mount_button.config(state="disabled")
        unmount_button.config(state="normal")
    else:
        status_label.config(text="●  SHARE UNMOUNTED", fg="red")
        detail_label.config(text="Host transfer folder is disconnected.")
        mount_button.config(state="normal")
        unmount_button.config(state="disabled")


def mount_share():
    os.makedirs(MOUNT_POINT, exist_ok=True)
    result = subprocess.run([
        "pkexec", "mount", "-t", "vboxsf", SHARE_NAME, MOUNT_POINT
    ])
    refresh_status()
    if result.returncode != 0 and not is_mounted():
        messagebox.showerror("Mount Failed", "The VirtualBox shared folder was not mounted.")


def unmount_share():
    result = subprocess.run(["pkexec", "umount", MOUNT_POINT])
    refresh_status()
    if result.returncode != 0 and is_mounted():
        messagebox.showerror("Unmount Failed", "The shared folder is still mounted.")


def open_folder():
    if not is_mounted():
        messagebox.showwarning("Share Disconnected", "Mount the transfer share before opening it.")
        return
    subprocess.Popen(["xdg-open", MOUNT_POINT])


root = tk.Tk()
root.title("REMnux Transfer Control")
root.geometry("480x320")
root.resizable(False, False)

 tk_title = tk.Label(root, text="REMnux Transfer Control", font=("Sans", 18, "bold"))
tk_title.pack(pady=(25, 15))

status_label = tk.Label(root, text="Checking...", font=("Sans", 16, "bold"))
status_label.pack(pady=5)

detail_label = tk.Label(root, text="", font=("Sans", 11))
detail_label.pack(pady=(0, 20))

button_frame = tk.Frame(root)
button_frame.pack()

mount_button = tk.Button(button_frame, text="MOUNT SHARE", width=16, height=2, command=mount_share)
mount_button.grid(row=0, column=0, padx=8)

unmount_button = tk.Button(button_frame, text="UNMOUNT SHARE", width=16, height=2, command=unmount_share)
unmount_button.grid(row=0, column=1, padx=8)

open_button = tk.Button(root, text="OPEN TRANSFER FOLDER", width=35, command=open_folder)
open_button.pack(pady=15)

refresh_button = tk.Button(root, text="Refresh Status", command=refresh_status)
refresh_button.pack()

path_label = tk.Label(root, text=MOUNT_POINT, font=("Sans", 9))
path_label.pack(pady=10)

refresh_status()


def periodic_check():
    refresh_status()
    root.after(2000, periodic_check)


root.after(2000, periodic_check)
root.mainloop()
