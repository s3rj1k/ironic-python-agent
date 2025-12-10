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
    method: "deb_oci_efi_lvm"         # when used without Metal3MachineTemplate
  rootDeviceHints:
    serialNumber: "foobar"            # Single disk
    # serialNumber: "foobar foobar2"  # RAID1 (two disks)

# Metal3MachineTemplate
spec:
  template:
    spec:
      customDeploy:
        method: "deb_oci_efi_lvm"

# BareMetalHost (annotation for OCI image)
metadata:
  annotations:
    bmh.metal3.io/oci_image: "debian:13"

# Metal3DataTemplate (maps annotation to configdrive metadata)
spec:
  metaData:
    fromAnnotations:
      - key: oci_image
        object: baremetalhost
        annotation: "bmh.metal3.io/oci_image"
```
