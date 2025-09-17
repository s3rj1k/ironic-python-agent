#!/bin/bash

# Doc: https://std.rocks/gnulinux_mdadm_uefi.html

set -Eeuo pipefail

trap 'echo "ERROR: Failed at line ${LINENO}: $BASH_COMMAND" >&2' ERR

export PATH="${PATH}:/bin:/usr/sbin:/sbin:/opt/bin"

STDIN_DATA=$(cat)

STAGE="$IPA_DEPLOYMENT_STAGE"
DEVICE="$IPA_TARGET_DEVICE"

case "$STAGE" in
	pre) ;;
	post)
		# Converting single disk ($DEVICE) installation to RAID1 (degraded mode)

		# Probe partitions
		if command -v partprobe > /dev/null 2>&1; then
			partprobe
		elif command -v blockdev > /dev/null 2>&1; then
			blockdev --rereadpt "$DEVICE" || true
		else
			blkid -p "$DEVICE" || true
		fi

		# Find root partition using PARTLABEL
		ROOT_PART=$(blkid -t PARTLABEL=root -l -o device)
		if [[ -z $ROOT_PART ]]; then
			echo "ERROR: Could not find partition with PARTLABEL=root"
			exit 1
		fi

		# Get root partition details
		ROOT_FS=$(blkid -s TYPE -o value "$ROOT_PART")
		ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
		ROOT_LABEL=$(blkid -s LABEL -o value "$ROOT_PART" 2> /dev/null || echo "")

		# Find EFI partition
		EFI_PART=$(blkid -t PARTLABEL=ESP -l -o device 2> /dev/null || echo "")

		# Mount root filesystem
		ROOT_MOUNT=$(mktemp -d /tmp/root.XXXXXX)
		mount -n -v -w "$ROOT_PART" "$ROOT_MOUNT"

		# Create backup in ramdisk root
		BACKUP_FILE="/rootfs-backup.tar.gz"

		# Change to root mount for relative paths
		cd "$ROOT_MOUNT"

		# Create backup excluding system directories
		tar -czpf "$BACKUP_FILE" \
			--exclude="./proc/*" \
			--exclude="./sys/*" \
			--exclude="./dev/*" \
			--exclude="./run/*" \
			--exclude="./tmp/*" \
			--exclude="./mnt/*" \
			--exclude="./media/*" \
			--exclude="./var/cache/apt/archives/*" \
			--one-file-system \
			--warning=no-file-changed \
			.

		# Return to original directory
		cd /

		# Unmount root filesystem
		umount -l "$ROOT_MOUNT"

		# Clear any existing RAID metadata
		mdadm --zero-superblock "$ROOT_PART" 2> /dev/null || true

		# Create degraded RAID1 array with only the target partition
		RAID_DEVICE="/dev/md0"

		# Stop any existing md0
		if [[ -b $RAID_DEVICE ]]; then
			mdadm --stop "$RAID_DEVICE" 2> /dev/null || true
		fi

		# Create RAID with 1.2 metadata
		mdadm --create "$RAID_DEVICE" \
			--level=1 \
			--raid-devices=2 \
			--metadata=1.2 \
			--name=root \
			--force \
			--run \
			"$ROOT_PART" \
			missing

		# Wait for RAID to be ready
		sync && sleep 5

		# Create filesystem on RAID with same UUID and label
		case "$ROOT_FS" in
			ext4)
				if [[ -n $ROOT_LABEL ]]; then
					mkfs.ext4 -F -U "$ROOT_UUID" -L "$ROOT_LABEL" "$RAID_DEVICE" || mkfs.ext4 -F "$RAID_DEVICE"
				else
					mkfs.ext4 -F -U "$ROOT_UUID" "$RAID_DEVICE" || mkfs.ext4 -F "$RAID_DEVICE"
				fi
				;;
			xfs)
				if [[ -n $ROOT_LABEL ]]; then
					mkfs.xfs -f -L "$ROOT_LABEL" "$RAID_DEVICE"
				else
					mkfs.xfs -f "$RAID_DEVICE"
				fi
				xfs_admin -U "$ROOT_UUID" "$RAID_DEVICE" 2> /dev/null || true
				;;
			btrfs)
				if [[ -n $ROOT_LABEL ]]; then
					mkfs.btrfs -f -L "$ROOT_LABEL" "$RAID_DEVICE"
				else
					mkfs.btrfs -f "$RAID_DEVICE"
				fi
				btrfstune -U "$ROOT_UUID" "$RAID_DEVICE" 2> /dev/null || true
				;;
			*)
				echo "ERROR: Unsupported filesystem: $ROOT_FS"
				exit 1
				;;
		esac

		# Mount RAID device
		mount -n -v -w "$RAID_DEVICE" "$ROOT_MOUNT"

		# Restore from backup
		cd "$ROOT_MOUNT"
		tar -xzpf "$BACKUP_FILE" --numeric-owner
		cd /

		# Get new UUID of RAID device
		RAID_UUID=$(blkid -s UUID -o value "$RAID_DEVICE")

		# Update fstab
		if [[ $RAID_UUID != "$ROOT_UUID" ]]; then
			sed -i "s|UUID=$ROOT_UUID|UUID=$RAID_UUID|g" "$ROOT_MOUNT/etc/fstab"
		fi

		# Also update device path references
		sed -i "s|$ROOT_PART|$RAID_DEVICE|g" "$ROOT_MOUNT/etc/fstab"

		# Mount necessary filesystems for chroot
		mount --bind /dev "$ROOT_MOUNT/dev"
		mount --bind /dev/pts "$ROOT_MOUNT/dev/pts"
		mount --bind /proc "$ROOT_MOUNT/proc"
		mount --bind /sys "$ROOT_MOUNT/sys"
		mount --bind /run "$ROOT_MOUNT/run"

		# Mount EFI if it exists
		if [[ -n $EFI_PART ]]; then
			mkdir -p "$ROOT_MOUNT/boot/efi"
			mount "$EFI_PART" "$ROOT_MOUNT/boot/efi"
		fi

		# Generate mdadm configuration
		mkdir -p "$ROOT_MOUNT/etc/mdadm"

		# Create mdadm.conf
		echo "# mdadm.conf" > "$ROOT_MOUNT/etc/mdadm/mdadm.conf"
		echo "HOMEHOST <system>" >> "$ROOT_MOUNT/etc/mdadm/mdadm.conf"
		echo "MAILADDR root" >> "$ROOT_MOUNT/etc/mdadm/mdadm.conf"
		echo "" >> "$ROOT_MOUNT/etc/mdadm/mdadm.conf"

		# Add array configuration
		mdadm --detail --scan --verbose | grep -E '^ARRAY' >> "$ROOT_MOUNT/etc/mdadm/mdadm.conf"

		# Update initramfs
		chroot "$ROOT_MOUNT" /bin/bash -c "update-initramfs -u -k all"

		# Update GRUB configuration
		GRUB_CONFIG="$ROOT_MOUNT/etc/default/grub"

		# Backup original config
		cp -v "$GRUB_CONFIG" "$GRUB_CONFIG.bak"

		# Add RAID boot parameters
		if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_CONFIG"; then
			if ! grep -q 'rootdelay=' "$GRUB_CONFIG"; then
				sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 rootdelay=10"/' "$GRUB_CONFIG"
			fi
		else
			echo 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash rootdelay=10"' >> "$GRUB_CONFIG"
		fi

		# Ensure RAID auto-assembly
		if grep -q '^GRUB_CMDLINE_LINUX=' "$GRUB_CONFIG"; then
			if ! grep -q 'rd.auto=1' "$GRUB_CONFIG"; then
				sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 rd.auto=1"/' "$GRUB_CONFIG"
			fi
		else
			echo 'GRUB_CMDLINE_LINUX="rd.auto=1"' >> "$GRUB_CONFIG"
		fi

		# Add RAID modules to preload
		if ! grep -q '^GRUB_PRELOAD_MODULES=' "$GRUB_CONFIG"; then
			echo 'GRUB_PRELOAD_MODULES="part_gpt part_msdos diskfilter mdraid1x mdraid09"' >> "$GRUB_CONFIG"
		fi

		# Disable UUID usage to use /dev/md0 directly
		if ! grep -q '^GRUB_DISABLE_LINUX_UUID=' "$GRUB_CONFIG"; then
			echo 'GRUB_DISABLE_LINUX_UUID=true' >> "$GRUB_CONFIG"
		fi

		# Install and update GRUB
		chroot "$ROOT_MOUNT" /bin/bash -c "
			set -e

			if [[ -d /boot/efi ]]; then
				grub-install --target=x86_64-efi --efi-directory=/boot/efi --recheck
			else
				grub-install --target=i386-pc --recheck $DEVICE
			fi

			update-grub
		"

		# Flush data to disks
		sync

		# Unmount EFI partition if it was mounted
		if [[ -d "$ROOT_MOUNT/boot/efi" ]] && mountpoint -q "$ROOT_MOUNT/boot/efi"; then
			umount -l "$ROOT_MOUNT/boot/efi"
		fi

		# Unmount necessary filesystems for chroot
		umount -l "$ROOT_MOUNT/run" || true
		umount -l "$ROOT_MOUNT/sys" || true
		umount -l "$ROOT_MOUNT/proc" || true
		umount -l "$ROOT_MOUNT/dev/pts" || true
		umount -l "$ROOT_MOUNT/dev" || true

		# Unmount the root filesystem
		umount -l "$ROOT_MOUNT"
		;;
	"")
		echo "ERROR: Empty deployment stage. IPA_DEPLOYMENT_STAGE environment variable not set."
		exit 1
		;;
	*)
		echo "ERROR: Unknown deployment stage: '$STAGE'. Expected 'pre' or 'post'."
		exit 1
		;;
esac
