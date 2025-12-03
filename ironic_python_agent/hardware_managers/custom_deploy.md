# Custom Deploy Hardware Manager

An IPA hardware manager that executes custom shell scripts during Metal3 bare metal provisioning, enabling flexible disk layouts, custom partitioning schemes, and alternative deployment strategies.

## Overview

The `CustomDeployHardwareManager` provides a deploy step that:
1. Extracts deployment configuration from Ironic node data
2. Fetches a custom script (local or remote)
3. Executes the script with full node context via JSON config files

## Script Sources

| Prefix                | Description                                    |
|-----------------------|------------------------------------------------|
| `http://`             | Remote script via HTTP                         |
| `https://`            | Remote script via HTTPS                        |
| `https+selfsigned://` | Remote script via HTTPS (skip cert validation) |
| `file://`             | Local filesystem path                          |
| *(no prefix)*         | Local filesystem path                          |

Remote URLs automatically receive `metal3_name` and `metal3_namespace` query parameters.

## Script Environment

Scripts receive configuration via `CUSTOM_DEPLOY_CONFIG_DIR` environment variable pointing to a directory with:

| File                    | Contents                                      |
|-------------------------|-----------------------------------------------|
| `node.json`             | Full Ironic node object                       |
| `ports.json`            | Network port objects for the node             |
| `configdrive.json`      | Configdrive (meta_data, user_data, network_data) |
| `root_device.json`      | Root device hints from instance_info          |
| `root_device_path.json` | Resolved block device path (e.g., `/dev/sda`) |
| `boot_mode.json`        | Boot mode (`uefi` or `bios`)                  |
| `secure_boot.json`      | Secure boot flag                              |
| `pxe_mac.json`          | PXE-enabled MAC address (null for virtual media) |
| `metal3_name.json`      | BareMetalHost name                            |
| `metal3_namespace.json` | BareMetalHost namespace                       |

## Configuration

The script location is specified via BMH annotation and propagated through Metal3DataTemplate:

```yaml
# BareMetalHost
metadata:
  annotations:
    bmh.metal3.io/custom_deploy: "http://server/deploy.sh"

# Metal3MachineTemplate
spec:
  template:
    spec:
      customDeploy:
        method: "custom_deploy"

# Metal3DataTemplate (maps annotation to configdrive)
metaData:
  fromAnnotations:
    - key: custom_deploy
      object: baremetalhost
      annotation: "bmh.metal3.io/custom_deploy"
```

## Debug Features

- **Debug sleep**: Add `ipa.debug_sleep_duration=<seconds>` to kernel cmdline
- **Interactive wait**: Waits for logged-in users (via KVM console) to disconnect before completing

## Remote Script Features

- Configurable retries (default: 3), timeout (default: 30s), and redirect limit (default: 5)
- Random jitter between retries to avoid thundering herd
