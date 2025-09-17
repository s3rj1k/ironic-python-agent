#!/bin/bash

set -Eeuo pipefail

trap 'echo "ERROR: Failed at line ${LINENO}: $BASH_COMMAND" >&2' ERR

export PATH="${PATH}:/bin:/usr/sbin:/sbin:/opt/bin"

STDIN_DATA=$(cat)

STAGE="$IPA_DEPLOYMENT_STAGE"
DEVICE="$IPA_TARGET_DEVICE"
MARKER_FILE="/ipa.hello"

case "$STAGE" in
	pre)
		echo "=== Pre-deployment stage ===" | tee "$MARKER_FILE"
		echo "Timestamp: $(date -Iseconds)" | tee -a "$MARKER_FILE"
		echo "Target device: $DEVICE" | tee -a "$MARKER_FILE"
		echo "Disk info:" | tee -a "$MARKER_FILE"
		lsblk "$DEVICE" | tee -a "$MARKER_FILE"
		echo "Metadata from stdin:" | tee -a "$MARKER_FILE"
		echo "$STDIN_DATA" | tee -a "$MARKER_FILE"
		echo "=== End pre-deployment ===" | tee -a "$MARKER_FILE"
		;;
	post)
		if [[ ! -f $MARKER_FILE ]]; then
			echo "ERROR: Pre-deployment marker file not found at $MARKER_FILE"
			exit 1
		fi

		MOUNT_POINT=$(mktemp -d)

		if command -v partprobe > /dev/null 2>&1; then
			partprobe
		elif command -v blockdev > /dev/null 2>&1; then
			blockdev --rereadpt "$DEVICE" || true
		else
			blkid -p "$DEVICE" || true
		fi

		ROOT_PARTITION=$(blkid -t PARTLABEL=root -l -o device)
		if [[ -z $ROOT_PARTITION ]]; then
			echo "ERROR: Root partition not found"
			exit 1
		fi

		EXISTING_MOUNT=$(findmnt -n -f -o TARGET "$ROOT_PARTITION" 2> /dev/null || true)
		if [[ -n $EXISTING_MOUNT ]]; then
			MOUNT_POINT="$EXISTING_MOUNT"
		else
			mount -n -v -w "$ROOT_PARTITION" "$MOUNT_POINT"
		fi

		TARGET_FILE="$MOUNT_POINT/$MARKER_FILE"
		mkdir -p "$(dirname "$TARGET_FILE")"
		cp -a "$MARKER_FILE" "$TARGET_FILE"
		chmod 644 "$TARGET_FILE"

		echo "=== Post-deployment stage ===" | tee -a "$TARGET_FILE"
		echo "Post-deployment timestamp: $(date -Iseconds)" | tee -a "$TARGET_FILE"
		echo "=== End post-deployment ===" | tee -a "$TARGET_FILE"

		sync
		if [[ -z $EXISTING_MOUNT ]]; then
			umount -l "$MOUNT_POINT"
		fi
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
