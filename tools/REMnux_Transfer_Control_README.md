# REMnux Transfer Control

A small Tkinter GUI for manually connecting and disconnecting a VirtualBox shared folder used to transfer analysis samples into a REMnux VM.

The purpose is to make the transfer state visible and easy to control without repeatedly typing mount and unmount commands.

## What It Does

- Shows the actual VirtualBox shared-folder mount status.
- Green `SHARE MOUNTED` status when the configured desktop directory is mounted as `vboxsf`.
- Red `SHARE UNMOUNTED` status when it is disconnected.
- Mount and Unmount buttons.
- Open Transfer Folder button.
- Automatically re-checks mount state every two seconds.
- Uses `pkexec` for privileged mount/unmount operations rather than storing a password in the script.

The status is verified with `findmnt`; the GUI does not assume that a mount or unmount succeeded just because a button was clicked.

## GUI Demonstration

### Share Unmounted

The red status confirms that the host transfer folder is disconnected from the REMnux VM.

**[INSERT IMAGE — SHARE UNMOUNTED HERE]**

### Share Mounted

The green status confirms that the VirtualBox shared folder is actively mounted and available to the REMnux VM.

**[INSERT IMAGE — SHARE MOUNTED HERE]**

The visual status is based on the actual `vboxsf` mount state rather than simply remembering which button was last pressed.

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

Useful checks:

```bash
modinfo vboxsf
python3 -m tkinter
which pkexec
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
Verify GUI shows SHARE UNMOUNTED
    ↓
Apply the required network isolation for the analysis
    ↓
Analyze a working copy
```

A shared folder is a transfer mechanism, not a malware containment boundary. Disconnect it before opening or analyzing an untrusted sample, and use appropriate VM isolation and snapshots.

## Design Principle

> Verify the actual state instead of assuming the requested action succeeded.

This utility was created as part of a hands-on REMnux malware-analysis lab workflow.
