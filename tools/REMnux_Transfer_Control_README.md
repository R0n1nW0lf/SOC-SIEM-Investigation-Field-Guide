# REMnux Transfer Control

A small Tkinter GUI for manually connecting and disconnecting a VirtualBox shared folder used to transfer analysis samples into a REMnux VM.

The purpose is to make the transfer state visible and easy to control without repeatedly typing mount and unmount commands.

## What It Does

- Shows the actual VirtualBox shared-folder mount status.
- Green `SHARE UNMOUNTED` status when the host transfer folder is disconnected.
- Red `SHARE MOUNTED` status when the host transfer folder is connected.
- Changes the desktop `REMnux-Transfer` folder icon to match the verified state.
- Green folder icon = unmounted / disconnected.
- Red folder icon = mounted / host connection open.
- Mount and Unmount buttons.
- Open Transfer Folder button.
- Automatically re-checks mount state every two seconds.
- Uses `pkexec` for privileged mount/unmount operations rather than storing a password in the script.

The status is verified with `findmnt`; the GUI does not assume that a mount or unmount succeeded just because a button was clicked.

## GUI Demonstration

### Share Unmounted — Green / Disconnected

The green GUI status and green desktop folder icon indicate that the host transfer folder is disconnected from the REMnux VM.

<img width="1193" height="899" alt="Remnux unmounted" src="https://github.com/user-attachments/assets/05e1a97c-9d0c-45de-bd45-b175b561c6e8" />

### Share Mounted — Red / Host Connection Open

The red GUI status and red desktop folder icon indicate that the VirtualBox shared folder is actively mounted and available to the REMnux VM.

<img width="1183" height="891" alt="remnux mounted" src="https://github.com/user-attachments/assets/5710e2f0-063d-45ed-b127-a43043281d85" />

The GUI and desktop folder provide two visual indicators of the same verified state. The status is based on the actual `vboxsf` mount state rather than simply remembering which button was last pressed.

## Default Configuration

The script expects the VirtualBox shared folder to be named:

```text
REMnux-Transfer
```

and uses this REMnux mount point:

```text
~/Desktop/REMnux-Transfer
```

VirtualBox Shared Folder settings should leave **Auto-mount disabled** if the goal is manual control.

## Requirements

- REMnux or another compatible Linux VM
- VirtualBox Guest Additions/shared-folder support (`vboxsf`)
- Python 3
- Tkinter
- `findmnt`
- `pkexec`
- `gio` for desktop folder icon metadata

Useful checks:

```bash
modinfo vboxsf
python3 -m tkinter
which pkexec
which gio
```

## Installation

Copy `remnux-transfer-control.py` to the REMnux home directory:

```bash
cp remnux-transfer-control.py ~/remnux-transfer-control.py
chmod +x ~/remnux-transfer-control.py
```

Create the desktop mount point:

```bash
mkdir -p ~/Desktop/REMnux-Transfer
```

Copy the included desktop launcher to the desktop and make it executable:

```bash
cp REMnux-Transfer-Control.desktop ~/Desktop/
chmod +x ~/Desktop/REMnux-Transfer-Control.desktop
```

Depending on the desktop environment, right-click the launcher and choose **Allow Launching** if prompted.

## Suggested Analysis Workflow

```text
Mount share
    ↓
Transfer sample/archive
    ↓
Copy it into the VM's incoming/uncleaned sample directory
    ↓
Unmount share
    ↓
Verify GUI shows GREEN SHARE UNMOUNTED
    ↓
Verify desktop transfer folder is GREEN
    ↓
Apply the required network isolation for the analysis
    ↓
Analyze a working copy
```

A shared folder is a transfer mechanism, not a malware containment boundary. Disconnect it before opening or analyzing an untrusted sample, and use appropriate VM isolation and snapshots.

## Visual Safety Principle

```text
GREEN = UNMOUNTED = DISCONNECTED
RED   = MOUNTED   = HOST CONNECTION OPEN
```

## Design Principle

> Verify the actual state instead of assuming the requested action succeeded.

This utility was created as part of a hands-on REMnux malware-analysis lab workflow.
