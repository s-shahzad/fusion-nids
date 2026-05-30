# VirtualBox Test Lab

## Recommendation

For this system, use **Oracle VirtualBox**.

Reasons:

- Windows 11 Home is a better fit for VirtualBox than a Hyper-V-centered lab
- `winget` can install VirtualBox on this machine
- no desktop VM platform is currently installed
- VirtualBox can keep the guest away from the host if you use the right network mode

## Safe Network Modes

### Best for one guest

Use **NAT** only.

- guest gets outbound internet if needed
- host is not directly exposed to inbound traffic from the guest
- simplest safe option for offline replay and tooling setup

### Best for multiple test VMs

Use **Internal Network**.

- VMs can talk to each other
- host is not on that virtual network
- best option for attacker-vm / target-vm traffic generation

### Do not use by default

Avoid **Host-Only Adapter** unless you explicitly need host-to-guest networking.

That mode creates a direct host-visible virtual network, which goes against the isolation goal.

## Recommended Lab Layout

### Single-VM lab

- one Ubuntu VM
- adapter 1: NAT
- no host-only adapter
- use this for offline replay, tools, packet generation experiments, and isolated workflow testing

### Exact first VM settings

- Name: `nids-ubuntu-lab`
- Guest OS type: `Ubuntu (64-bit)`
- Memory: `8192 MB`
- CPUs: `4`
- Disk: `60 GB` dynamically allocated VDI
- Video memory: `32 MB`
- Graphics controller: `VMSVGA`
- Boot order: `DVD`, then `Disk`
- Audio: `Disabled`
- USB: `Disabled`
- Shared clipboard: `Disabled`
- Drag and drop: `Disabled`
- Network adapter 1: `NAT`
- Adapter 1 type: `VirtIO`
- Promiscuous mode: `Deny`
- `Host-Only Adapter`: not configured
- `Bridged Adapter`: not configured

These settings are meant to keep the guest useful but separated from the Windows host.

### Multi-VM lab

- `attacker-vm`
- `target-vm`
- optional `sensor-vm`
- adapter 1 on all VMs: Internal Network named `nidslab`
- optional second adapter on one VM: NAT, only if you need package updates

### Best realistic lab for this system

Use:

- `nids-kali-attacker`: cloned from the existing `kali` VM
- `nids-ubuntu-target`: Ubuntu Server target
- `nids-ubuntu-sensor`: Ubuntu Server sensor

Recommended adapter layout:

- `nids-kali-attacker`
  - Adapter 1: `Internal Network` = `nidslab`
  - no NAT
  - no Host-Only
  - no Bridged
- `nids-ubuntu-target`
  - Adapter 1: `Internal Network` = `nidslab`
  - Adapter 2: none by default
- `nids-ubuntu-sensor`
  - Adapter 1: `Internal Network` = `nidslab`
  - Adapter 1 promiscuous mode: `Allow All`
  - Adapter 2: none by default

This is the most realistic safe lab because the host stays off the attack network while the sensor can still observe east-west guest traffic. If you need package updates, attach a temporary second `NAT` adapter only during provisioning and remove it again afterward.

## Install

Open **PowerShell as Administrator** and run:

```powershell
PowerShell -ExecutionPolicy Bypass -File C:\NIDS_Workspace\scripts\setup_virtualbox_lab.ps1 -InstallVirtualBox
```

## Create The First VM

After VirtualBox is installed, create the first Ubuntu lab VM with:

```powershell
PowerShell -ExecutionPolicy Bypass -File C:\NIDS_Workspace\scripts\create_virtualbox_lab_vm.ps1 -VMName nids-ubuntu-lab -LabRoot C:\NIDS_Workspace\NIDS_TestLab -IsoPath C:\NIDS_Workspace\NIDS_TestLab\isos\ubuntu.iso
```

Or use the wrapper inside the lab folder:

```powershell
C:\NIDS_Workspace\NIDS_TestLab\CREATE_FIRST_VM.ps1 -IsoPath C:\NIDS_Workspace\NIDS_TestLab\isos\ubuntu.iso
```

The wrapper creates:

- `nids-ubuntu-lab`
- `8 GB` RAM
- `4` vCPUs
- `60 GB` disk
- `NAT` networking only

## Create The Realistic Lab

Use the realistic builder when you want attacker/target/sensor isolation instead of a single utility VM:

```powershell
PowerShell -ExecutionPolicy Bypass -File C:\NIDS_Workspace\scripts\build_realistic_virtualbox_lab.ps1 -LabRoot C:\NIDS_Workspace\NIDS_TestLab -AttachIso -UbuntuIsoPath C:\NIDS_Workspace\NIDS_TestLab\isos\ubuntu-24.04.4-live-server-amd64.iso
```

Or let it fetch the official Ubuntu ISO first:

```powershell
PowerShell -ExecutionPolicy Bypass -File C:\NIDS_Workspace\scripts\build_realistic_virtualbox_lab.ps1 -LabRoot C:\NIDS_Workspace\NIDS_TestLab -DownloadUbuntuIso
```

## Lab Files

The local lab root is:

`C:\NIDS_Workspace\NIDS_TestLab`

Useful folders:

- `isos\`
- `vm_exports\`
- `pcaps\`
- `reports\`
- `logs\`

## Testing Flow

1. Install VirtualBox.
2. Place an Ubuntu ISO in `C:\NIDS_Workspace\NIDS_TestLab\isos\`.
3. Create a VM using NAT only.
4. Install Ubuntu inside the guest.
5. Put your PCAPs in `C:\NIDS_Workspace\NIDS_TestLab\pcaps`.
6. Run offline replay from the host or from the lab workflow you prepared.
7. Generate threshold guidance after replay.
8. Later, build the multi-VM internal-network lab for load and attack testing.
