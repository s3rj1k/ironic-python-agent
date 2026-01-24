# Debian/Ubuntu OCI EFI LVM Deploy Hardware Manager

An IPA hardware manager that deploys Debian-based OCI container images with EFI boot, LVM root filesystem, and optional RAID1 support.

## Overview

The `DebOCIEFILVMHardwareManager` provides a deploy step that:
1. Resolves target disk(s) from root device hints
2. Partitions disk(s) with EFI and LVM (optionally on RAID1)
3. Extracts OCI container image as rootfs using `crane`
4. Installs bootloader, kernel, and cloud-init configuration

## Configuration

```yaml
# BareMetalHost
spec:
  bootMode: UEFI
  customDeploy:
    method: "deb_oci_efi_lvm"          # when used without Metal3MachineTemplate
  image:
    url: "oci://debian:13"             # OCI image via spec.image.url
  rootDeviceHints:
    serialNumber: "foobar"             # Single disk serial
    # wwn: "0x123456789"               # Single disk WWN
    # serialNumber: "foobar foobar2"   # RAID1 serial
    # wwn: "0x123456789 0x987654321"   # RAID1 WWN

# Metal3MachineTemplate
spec:
  template:
    spec:
      customDeploy:
        method: "deb_oci_efi_lvm"

# Using annotations for OCI image and root device hints (takes priority over rootDeviceHints)
metadata:
  annotations:
    bmh.metal3.io/oci_image: "debian:13"
    # bmh.metal3.io/root_device_hints: "serial=ABC123"                # Single disk serial
    # bmh.metal3.io/root_device_hints: "wwn=0x123456789"              # Single disk WWN
    # bmh.metal3.io/root_device_hints: "serial=ABC123 DEF456"         # RAID1 serial
    # bmh.metal3.io/root_device_hints: "wwn=0x123456789 0x987654321"  # RAID1 WWN
    # bmh.metal3.io/disk_wipe_mode: "all"                             # Wipe all disks
    # bmh.metal3.io/disk_wipe_mode: "target"                          # Wipe only target disk(s)

# Metal3DataTemplate (maps annotation to configdrive metadata)
spec:
  metaData:
    fromAnnotations:
      - key: oci_image
        object: baremetalhost
        annotation: "bmh.metal3.io/oci_image"
      - key: root_device_hints
        object: baremetalhost
        annotation: "bmh.metal3.io/root_device_hints"
      - key: disk_wipe_mode
        object: baremetalhost
        annotation: "bmh.metal3.io/disk_wipe_mode"
```

### Disk Wipe Mode

Controls which disks are cleaned before deployment:
- `all` - Wipe all block devices (prevents stray RAID/LVM metadata)
- `target` - Wipe only the target disk(s) from root_device_hints
- Not specified - Default: `all` for RAID1, `target` for single disk
