#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 s3rj1k

set -euxo pipefail

readonly UBUNTU_AMD64_IMAGE_URL="https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64.squashfs"
readonly UBUNTU_ARM64_IMAGE_URL="https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-arm64.squashfs"

readonly RAID_DEVICE="/dev/md0"
readonly VG_NAME="vg_root"
readonly LV_NAME="lv_root"
readonly ROOT_FS_LABEL="ROOTFS"
readonly BOOT_FS_LABEL="EFI"
readonly BOOT_FS_LABEL2="EFI2"

case "$(uname -m)" in
	x86_64)
		readonly SQUASHFS_URL="$UBUNTU_AMD64_IMAGE_URL"
		readonly UEFI_TARGET="x86_64-efi"
		readonly GRUB_PACKAGES="grub-efi-amd64 grub-efi-amd64-signed shim-signed"
		;;
	aarch64)
		readonly SQUASHFS_URL="$UBUNTU_ARM64_IMAGE_URL"
		readonly UEFI_TARGET="arm64-efi"
		readonly GRUB_PACKAGES="grub-efi-arm64 grub-efi-arm64-bin"
		;;
	*)
		exit 1
		;;
esac

readonly CONFIG_DIR="${CUSTOM_DEPLOY_CONFIG_DIR:-}"
readonly CONFIGDRIVE_FILE="$CONFIG_DIR/configdrive.json"
readonly ROOT_DEVICE_PATH_FILE="$CONFIG_DIR/root_device_path.json"

if [[ ! -f $CONFIGDRIVE_FILE ]]; then
	exit 1
fi

if [[ ! -f $ROOT_DEVICE_PATH_FILE ]]; then
	exit 1
fi

clean_device()
{
	local device="$1"

	lsblk -nlo NAME,TYPE "$device" 2> /dev/null |
		awk '$2=="raid1" || $2=="raid0" || $2=="raid5" || $2=="raid6" || $2=="raid10" {print "/dev/"$1}' |
		xargs -rI{} mdadm --stop {} || true

	if pvs "$device"; then
		local vg_name=""
		vg_name=$(pvs --noheadings -o vg_name "$device" 2> /dev/null | xargs || echo "")

		if [[ -n $vg_name ]]; then
			lvs --noheadings -o lv_path "$vg_name" 2> /dev/null | xargs -rI{} lvremove -f {} || true
			vgremove -f "$vg_name" || true
		fi

		pvremove -ff -y "$device" || true
	fi

	mdadm --zero-superblock --force "$device" || true
	lsblk -nlo NAME "$device" 2> /dev/null |
		grep -v "^$(basename "$device")$" |
		sed 's|^|/dev/|' |
		xargs -rI{} mdadm --zero-superblock --force {} || true

	lsblk -nlo NAME "$device" 2> /dev/null |
		grep -v "^$(basename "$device")$" |
		sed 's|^|/dev/|' |
		xargs -rI{} wipefs --all --force {} || true

	wipefs --all --force "$device" || true
	sgdisk --zap-all "$device" || true

	sleep 5

	partprobe "$device" || true

	return 0
}

resolv_conf()
{
	local chroot_dir="$1"
	local symlink_target=""
	local target_path=""

	symlink_target=$(readlink "$chroot_dir/etc/resolv.conf")
	if [[ $symlink_target == /* ]]; then
		target_path="$chroot_dir$symlink_target"
	else
		target_path="$chroot_dir/etc/$symlink_target"
	fi

	mkdir -p "$(dirname "$target_path")"

	if ! cp /etc/resolv.conf "$target_path"; then
		return 1
	fi

	return 0
}

setup_chroot()
{
	local chroot_dir="$1"

	if ! mount -t proc proc "$chroot_dir/proc"; then
		return 1
	fi

	if ! mount -t sysfs sys "$chroot_dir/sys"; then
		return 1
	fi

	if ! mount --bind /dev "$chroot_dir/dev"; then
		return 1
	fi

	if ! mount --bind /dev/pts "$chroot_dir/dev/pts"; then
		return 1
	fi

	mkdir -p "$chroot_dir/run"

	if ! resolv_conf "$chroot_dir"; then
		return 1
	fi

	return 0
}

teardown_chroot()
{
	local chroot_dir="$1"

	if mountpoint -q "$chroot_dir/run"; then
		if ! umount -l "$chroot_dir/run"; then
			return 1
		fi
	fi

	if mountpoint -q "$chroot_dir/dev/pts"; then
		if ! umount -l "$chroot_dir/dev/pts"; then
			return 1
		fi
	fi

	if mountpoint -q "$chroot_dir/dev"; then
		if ! umount -l "$chroot_dir/dev"; then
			return 1
		fi
	fi

	if mountpoint -q "$chroot_dir/sys"; then
		if ! umount -l "$chroot_dir/sys"; then
			return 1
		fi
	fi

	if mountpoint -q "$chroot_dir/proc"; then
		if ! umount -l "$chroot_dir/proc"; then
			return 1
		fi
	fi

	return 0
}

get_partition_path()
{
	local device="$1"
	local partition_number="$2"

	if [[ $device =~ nvme[0-9]+n[0-9]+$ ]] || [[ $device =~ mmcblk[0-9]+$ ]]; then
		echo "${device}p${partition_number}"
	else
		echo "${device}${partition_number}"
	fi

	return 0
}

get_second_device()
{
	local configdrive_file="$1"
	local second_serial=""
	local second_device=""

	second_serial=$(jq -r '.meta_data.raid_second_device_serial // empty' "$configdrive_file" 2> /dev/null)
	if [[ -z $second_serial ]] || [[ $second_serial == "null" ]]; then
		echo ""
		return 0
	fi

	second_device=$(lsblk -ndo NAME,SERIAL 2> /dev/null | awk -v serial="$second_serial" '$2 == serial {print "/dev/" $1; exit}')
	echo "$second_device"
	return 0
}

wait_for_device()
{
	local device="$1"
	local attempt=0

	while [[ $attempt -lt 5 ]]; do
		if [[ -b $device ]]; then
			return 0
		fi
		sleep 5
		attempt=$((attempt + 1))
	done

	return 1
}

partition_disk()
{
	local device="$1"
	local vg_name="$2"
	local lv_name="$3"
	local second_device="${4:-}"
	local raid_device="$5"

	if ! wait_for_device "$device"; then
		return 1
	fi

	if ! parted -s "$device" mklabel gpt; then
		return 1
	fi

	if ! parted -s -a optimal "$device" mkpart primary fat32 2MiB 2050MiB; then
		return 1
	fi

	if ! parted -s "$device" set 1 esp on; then
		return 1
	fi

	if ! parted -s -a optimal "$device" mkpart primary 2050MiB 99%; then
		return 1
	fi

	if [[ -n $second_device ]]; then
		if ! parted -s "$device" set 2 raid on; then
			return 1
		fi
	else
		if ! parted -s "$device" set 2 lvm on; then
			return 1
		fi
	fi

	lsblk -nlo NAME "$device" 2> /dev/null |
		grep -v "^$(basename "$device")$" |
		sed 's|^|/dev/|' |
		xargs -rI{} wipefs -a {} 2> /dev/null || true

	local data_partition=""
	data_partition=$(get_partition_path "$device" 2) || {
		return 1
	}

	local pv_device="$data_partition"

	if [[ -n $second_device ]]; then
		partprobe "$device" || true
		partprobe "$second_device" || true
		sleep 5

		if ! wait_for_device "$second_device"; then
			return 1
		fi

		if ! sfdisk -d "$device" | sfdisk "$second_device"; then
			return 1
		fi

		if ! sgdisk --partition-guid=1:R "$second_device"; then
			return 1
		fi

		if ! sgdisk --partition-guid=2:R "$second_device"; then
			return 1
		fi

		partprobe "$second_device" || true
		sleep 5

		local second_data_partition=""
		second_data_partition=$(get_partition_path "$second_device" 2) || {
			return 1
		}

		if [[ ! -b $second_data_partition ]]; then
			return 1
		fi

		local homehost=""
		homehost=$(jq -r '.meta_data["metal3-name"] // empty' "$CONFIGDRIVE_FILE")
		if [[ -z $homehost ]] || [[ $homehost == "null" ]]; then
			return 1
		fi

		if ! mdadm --create "$raid_device" \
			--level=1 \
			--raid-devices=2 \
			--metadata=1.2 \
			--name=root \
			--bitmap=internal \
			--homehost="$homehost" \
			--force \
			--run \
			--assume-clean \
			"$data_partition" \
			"$second_data_partition"; then
			return 1
		fi

		sync
		sleep 5

		pv_device="$raid_device"
	else
		partprobe "$device" || true
		sleep 5
	fi

	if ! pvcreate -ff -y --zero y "$pv_device"; then
		return 1
	fi

	if ! vgcreate -y "$vg_name" "$pv_device"; then
		return 1
	fi

	if ! lvcreate -y -W y -n "$lv_name" -l "100%FREE" "$vg_name"; then
		return 1
	fi

	return 0
}

configure_cloud_init()
{
	local mount_point="$1"

	local cloud_init_cfg_dir="$mount_point/etc/cloud/cloud.cfg.d"
	mkdir -p "$cloud_init_cfg_dir" || {
		return 1
	}

	local nocloud_seed_dir="$mount_point/var/lib/cloud/seed/nocloud-net"
	mkdir -p "$nocloud_seed_dir" || {
		return 1
	}

	local meta_data_json user_data_str network_data_json

	meta_data_json=$(jq -c '.meta_data // {}' "$CONFIGDRIVE_FILE" 2> /dev/null || echo "{}")
	user_data_str=$(jq -r '.user_data // ""' "$CONFIGDRIVE_FILE" 2> /dev/null || echo "")
	network_data_json=$(jq -c '.network_data // {}' "$CONFIGDRIVE_FILE" 2> /dev/null || echo "{}")

	cat > "$cloud_init_cfg_dir/99-nocloud-seed.cfg" << 'EOF'
datasource_list: [ NoCloud, None ]
datasource:
  NoCloud:
    seedfrom: file:///var/lib/cloud/seed/nocloud-net/
EOF

	echo "$meta_data_json" | yq -P > "$nocloud_seed_dir/meta-data" || {
		return 1
	}

	echo "$user_data_str" > "$nocloud_seed_dir/user-data" || {
		return 1
	}

	if [[ $network_data_json != "{}" ]]; then
		echo "$network_data_json" | yq -P > "$nocloud_seed_dir/network-config" || {
			return 1
		}
	fi

	chmod 600 "$nocloud_seed_dir"/* || true

	return 0
}

packages()
{
	local chroot_dir="$1"

	if [[ -x $chroot_dir/usr/bin/snap ]]; then
		chroot "$chroot_dir" snap list 2> /dev/null | awk '!/^Name|^core|^snapd|^lxd/ {print $1}' | xargs -rI{} snap remove --purge {} || true
		chroot "$chroot_dir" snap list 2> /dev/null | awk '/^lxd/ {print $1}' | xargs -rI{} snap remove --purge {} || true
		chroot "$chroot_dir" snap list 2> /dev/null | awk '/^core/ {print $1}' | xargs -rI{} snap remove --purge {} || true
		chroot "$chroot_dir" snap list 2> /dev/null | awk '/^snapd/ {print $1}' | xargs -rI{} snap remove --purge {} || true
		chroot "$chroot_dir" snap list 2> /dev/null | awk '!/^Name/ {print $1}' | xargs -rI{} snap remove --purge {} || true
	fi

	if ! chroot "$chroot_dir" apt-get update; then
		return 1
	fi

	chroot "$chroot_dir" apt-get --purge remove -y lxd lxd-agent-loader lxd-installer snapd || true

	# shellcheck disable=SC2086
	if ! chroot "$chroot_dir" apt-get install -y cloud-init grub-common lvm2 mdadm rsync $GRUB_PACKAGES; then
		return 1
	fi

	local version_id=""
	version_id=$(grep "^VERSION_ID=" "$chroot_dir/etc/os-release" | cut -d= -f2 | tr -d '"') || true
	if [[ -n $version_id ]]; then
		chroot "$chroot_dir" apt-get install -y "linux-generic-hwe-${version_id}" || true
	fi

	local rc_packages=""
	rc_packages=$(chroot "$chroot_dir" dpkg -l 2> /dev/null | grep '^rc' | awk '{print $2}' | xargs 2> /dev/null) || true
	if [[ -n $rc_packages ]]; then
		# shellcheck disable=SC2086
		chroot "$chroot_dir" apt-get purge -y $rc_packages || true
	fi

	chroot "$chroot_dir" apt-get autoremove --purge -y || true

	return 0
}

filesystems()
{
	local efi_partition="$1"
	local root_lv_path="$2"
	local boot_label="$3"
	local root_label="$4"
	local second_efi_partition="${5:-}"
	local boot_label2="${6:-}"

	if ! mkfs.vfat -F 32 -n "$boot_label" "$efi_partition"; then
		return 1
	fi

	if [[ -n $second_efi_partition ]]; then
		mkfs.vfat -F 32 -n "$boot_label2" "$second_efi_partition" || true
	fi

	if ! mkfs.ext4 -F -L "$root_label" "$root_lv_path"; then
		return 1
	fi

	return 0
}

fstab()
{
	local mount_point="$1"
	local root_label="$2"
	local boot_label="$3"
	local is_raid="$4"
	local boot_label2="${5:-}"

	if ! printf "LABEL=%s\t%s\t%s\t%s\t%s\t%s\n" "$root_label" "/" "ext4" "errors=remount-ro" "0" "1" > "$mount_point/etc/fstab"; then
		return 1
	fi

	if ! printf "LABEL=%s\t%s\t%s\t%s\t%s\t%s\n" "$boot_label" "/boot/efi" "vfat" "umask=0077,nofail" "0" "1" >> "$mount_point/etc/fstab"; then
		return 1
	fi

	if [[ $is_raid == "true" ]]; then
		printf "LABEL=%s\t%s\t%s\t%s\t%s\t%s\n" "$boot_label2" "/boot/efi2" "vfat" "umask=0077,nofail,noauto" "0" "2" >> "$mount_point/etc/fstab" || {
			return 1
		}
	fi

	return 0
}

mdadm_conf()
{
	local mount_point="$1"

	if ! mkdir -p "$mount_point/etc/mdadm"; then
		return 1
	fi

	local mdadm_conf="$mount_point/etc/mdadm/mdadm.conf"

	cat > "$mdadm_conf" <<- 'EOF'
		HOMEHOST <system>
		MAILADDR root
	EOF

	if ! mdadm --detail --scan --verbose | grep -E '^ARRAY' >> "$mdadm_conf"; then
		return 1
	fi

	return 0
}

setup_grub_defaults()
{
	local chroot_dir="$1"
	local root_label="$2"
	local is_raid="$3"
	local grub_default="$chroot_dir/etc/default/grub"

	local grub_cmdline="root=LABEL=$root_label"
	if [[ $is_raid == "true" ]]; then
		grub_cmdline="$grub_cmdline rd.auto=1"
	fi

	if ! sed -i "s|^#*\s*GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$grub_cmdline\"|" "$grub_default"; then
		return 1
	fi

	sed -i "s|^#*\s*GRUB_DISABLE_LINUX_UUID=.*|GRUB_DISABLE_LINUX_UUID=true|" "$grub_default"
	if ! grep -q "^GRUB_DISABLE_LINUX_UUID=" "$grub_default"; then
		echo "GRUB_DISABLE_LINUX_UUID=true" >> "$grub_default"
	fi

	if [[ $is_raid == "true" ]]; then
		if grep -q "^#*\s*GRUB_CMDLINE_LINUX_DEFAULT=" "$grub_default"; then
			if ! grep -q "rootdelay=" "$grub_default"; then
				sed -i "s|^#*\s*GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"|GRUB_CMDLINE_LINUX_DEFAULT=\"\1 rootdelay=10\"|" "$grub_default"
			fi
		else
			echo 'GRUB_CMDLINE_LINUX_DEFAULT="rootdelay=10"' >> "$grub_default"
		fi
	fi

	return 0
}

setup_grub_efi_sync()
{
	local chroot_dir="$1"
	local boot_label2="$2"
	local grub_hook="$chroot_dir/etc/grub.d/90_copy_to_boot_efi2"

	cat > "$grub_hook" << EOF
#!/bin/sh
# Sync GRUB updates to both EFI partitions for RAID redundancy
set -e

if mountpoint --quiet --nofollow /boot/efi; then
    mount LABEL=$boot_label2 /boot/efi2 || :
    rsync --times --recursive --delete /boot/efi/ /boot/efi2/
    umount -l /boot/efi2
fi
exit 0
EOF

	chmod +x "$grub_hook" || {
		return 1
	}

	return 0
}

root_device=$(jq -r '. // empty' "$ROOT_DEVICE_PATH_FILE") || {
	exit 1
}

if ! wait_for_device "$root_device"; then
	exit 1
fi

if ! clean_device "$root_device"; then
	exit 1
fi

second_device=$(get_second_device "$CONFIGDRIVE_FILE")

if [[ -n $second_device ]]; then
	if ! wait_for_device "$second_device"; then
		second_device=""
	elif ! clean_device "$second_device"; then
		second_device=""
	fi
fi

is_raid="false"
if [[ -n $second_device ]]; then
	is_raid="true"
fi

if ! partition_disk "$root_device" "$VG_NAME" "$LV_NAME" "$second_device" "$RAID_DEVICE"; then
	exit 1
fi

efi_partition=$(get_partition_path "$root_device" 1) || {
	exit 1
}

second_efi_partition=""
if [[ $is_raid == "true" ]]; then
	second_efi_partition=$(get_partition_path "$second_device" 1) || true
fi

root_lv_path="/dev/$VG_NAME/$LV_NAME"

if ! filesystems "$efi_partition" "$root_lv_path" "$BOOT_FS_LABEL" "$ROOT_FS_LABEL" "$second_efi_partition" "$BOOT_FS_LABEL2"; then
	exit 1
fi

ROOT_MOUNT=$(mktemp -d) || {
	exit 1
}

if ! mount "$root_lv_path" "$ROOT_MOUNT"; then
	exit 1
fi

download_dir=$(mktemp -d) || {
	exit 1
}

SQUASHFS_FILE="$download_dir/rootfs.squashfs"

if ! curl -sSL -o "$SQUASHFS_FILE" "$SQUASHFS_URL"; then
	exit 1
fi

if ! unsquashfs -f -d "$ROOT_MOUNT" "$SQUASHFS_FILE"; then
	exit 1
fi

if ! mkdir -p "$ROOT_MOUNT/boot/efi"; then
	exit 1
fi

if ! mount "$efi_partition" "$ROOT_MOUNT/boot/efi"; then
	exit 1
fi

if ! setup_chroot "$ROOT_MOUNT"; then
	exit 1
fi

if ! packages "$ROOT_MOUNT"; then
	exit 1
fi

if ! configure_cloud_init "$ROOT_MOUNT"; then
	exit 1
fi

if ! fstab "$ROOT_MOUNT" "$ROOT_FS_LABEL" "$BOOT_FS_LABEL" "$is_raid" "$BOOT_FS_LABEL2"; then
	exit 1
fi

if ! setup_grub_defaults "$ROOT_MOUNT" "$ROOT_FS_LABEL" "$is_raid"; then
	exit 1
fi

if [[ $is_raid == "true" ]]; then
	if ! mdadm_conf "$ROOT_MOUNT"; then
		exit 1
	fi

	if ! setup_grub_efi_sync "$ROOT_MOUNT" "$BOOT_FS_LABEL2"; then
		exit 1
	fi

	mkdir -p "$ROOT_MOUNT/boot/efi2" || {
		exit 1
	}
fi

if ! chroot "$ROOT_MOUNT" update-grub; then
	exit 1
fi

if ! chroot "$ROOT_MOUNT" update-initramfs -u -k all; then
	exit 1
fi

if ! chroot "$ROOT_MOUNT" grub-install --target="$UEFI_TARGET" --efi-directory=/boot/efi --bootloader-id=ubuntu --recheck; then
	exit 1
fi

if [[ $is_raid == "true" ]]; then
	if mount "$second_efi_partition" "$ROOT_MOUNT/boot/efi2"; then
		rsync -a "$ROOT_MOUNT/boot/efi/" "$ROOT_MOUNT/boot/efi2/"
		chroot "$ROOT_MOUNT" grub-install --target="$UEFI_TARGET" --efi-directory=/boot/efi2 --bootloader-id=ubuntu --recheck
		if mountpoint -q "$ROOT_MOUNT/boot/efi2"; then
			umount -l "$ROOT_MOUNT/boot/efi2"
		fi
	fi
fi

if ! teardown_chroot "$ROOT_MOUNT"; then
	exit 1
fi

if mountpoint -q "$ROOT_MOUNT/boot/efi"; then
	if ! umount -l "$ROOT_MOUNT/boot/efi"; then
		exit 1
	fi
fi

if mountpoint -q "$ROOT_MOUNT"; then
	if ! umount -l "$ROOT_MOUNT"; then
		exit 1
	fi
fi
