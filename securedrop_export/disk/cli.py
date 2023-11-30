import logging
import json
import os
import subprocess
import pdb

from typing import List, Optional, Union

from securedrop_export.exceptions import ExportException

from .volume import EncryptionScheme, FileSystemType, Volume, MountedVolume
from .status import Status

logger = logging.getLogger(__name__)


class CLI:
    """
    A Python wrapper for various shell commands required to detect, map, and
    mount Export devices.

    CLI callers must handle ExportException and all exceptions and exit with
    sys.exit(0) so that another program does not attempt to open the submission.
    """

    # Default mountpoint (unless drive is already mounted manually by the user)
    _DEFAULT_MOUNTPOINT = "/media/usb"
    _DEFAULT_VC_CONTAINER_NAME = "vc-volume"

    def get_volumes(self) -> Volume:
        """
        See if we have a valid connected device.
        Throws ExportException.
        """
        try:
            # lsblk -o NAME,RM,RO,TYPE,MOUNTPOINT,FSTYPE --json
            lsblk = subprocess.check_output(
                ["lsblk", "-o", "NAME,RM,RO,TYPE,MOUNTPOINT,FSTYPE", "--json"]
            ).decode("utf-8")
            all_devices = json.loads(lsblk)

            # Removable, non-read-only disks
            removable_devices = [
                item
                for item in all_devices.get("blockdevices")
                if item.get("type") == "disk"
                and item.get("rm") == True
                and item.get("ro") == False
            ]

            if len(removable_devices) == 0:
                raise ExportException(sdstatus=Status.NO_DEVICE_DETECTED)
            elif len(removable_devices) > 1:
                # For now we only support inserting one device at a time
                raise ExportException(sdstatus=Status.MULTI_DEVICE_DETECTED)
            else:
                return self._parse_single_device(removable_devices[0])

        except subprocess.CalledProcessError:
            raise ExportException(sdstatus=Status.DEVICE_ERROR)

        except ExportException:
            raise

    def _parse_single_device(self, device: dict) -> Volume:
        """
        Given a dictionary corresponding to the JSON-formatted lsblk output for
        one device, determine if it is suitably partitioned and return
        Volume to be used for export.

        A disk will have nested output, with the partitions appearing
        as 'children.'

        It would be possible to parse and accept a highly nested partition scheme,
        but for simplicity, accept only disks that have an encrypted partition at
        either the whole-device level or the first partition level.

        Returns Volume or throws ExportException.

        This is an example disk with a single encrypted partition:
        {'name': 'sda', 'rm': True, 'ro': False, 'type': 'disk', 'mountpoint': None, 'fstype': None, 'children': [{'name': 'vc', 'rm': False, 'ro': False, 'type': 'crypt', 'mountpoint': None, 'fstype': 'vfat'}]}
        """
        volumes = []

        if "children" in block_device:
            for entry in block_device.get("children"):
                # This would be /dev/sdX1, /dev/sdX2 etc
                if "children" in entry:
                    for partition in entry.get("children"):
                        volumes.append(self._get_volume_info(entry, partition))

                # This would be /dev/sdX
                else:
                    volumes.append(self._get_volume_info(block_device, entry))

            if len(volumes) != 1:
                logger.error(f"Need one target on {block_device}, got {len(volumes)}")
                raise ExportException(sdstatus=Status.INVALID_DEVICE_DETECTED)

        raise ExportException(sdstatus=Status.INVALID_DEVICE_DETECTED)

    def _get_volume_info(
        self, device, partition
    ) -> Optional[Union[Volume, MountedVolume]]:
        """
        Get eligible volume info.
        Will only return devices that are confirmed supported (meaning, LUKS drives
        or unlocked Veracrypt drives. Locked Veracrypt drives are excluded)
        """
        mapped_name = partition.get("name")
        fstype = self._parse_fstype(partition.get("fstype"))
        device_name = device.get("name")
        mountpoint = device.get("mountpoint")

        if mountpoint is not None:
            encryption = self._get_cryptsetup_info(mountpoint)
            return MountedVolume(
                device_name=device_name,
                mapped_name=mapped_name,
                encryption=encryption,
                fstype=fstype,
                mountpoint=mountpoint,
            )

        elif partition.get("type") == "crypt" and device.get("fstype") == "crypto_LUKS":
            encryption = EncryptionScheme.LUKS
            return Volume(
                device_name=device_name,
                mapped_name=mapped_name,
                encryption=encryption,
                fstype=fstype,
            )

    def _get_cryptsetup_info(self, entry) -> EncryptionScheme:
        status = (
            subprocess.check_output(
                ["sudo", "cryptsetup", "status", f"/dev/mapper/{entry}"]
            )
            .decode("utf-8")
            .split("\n  ")
        )

        if "type:    TCRYPT" in status:
            return EncryptionScheme.VERACRYPT
        elif "type:    LUKS1" in status or "type:    LUKS2" in status:
            return EncryptionScheme.LUKS
        else:
            logger.error("Unknown encryption scheme")
            raise ExportException(sdstatus=Status.INVALID_DEVICE_DETECTED)

    def _parse_fstype(self, value: str) -> FileSystemType:
        try:
            return FileSystemType(value)
        except ValueError as v:
            # We're not trying that hard, so this isn't an error
            logger.info("Could not determine filesystem type.")
            logger.debug(v)
            return FileSystemType.UNKNOWN

    def __parse_children_recursive(self, parent_device: str, nested_devices: list):
        """
        Parse json-formatted results of `lsblk`, which can include nested partitions.
        Not in use.
        """
        for item in nested_devices:
            if "children" in item:
                logger.debug("cheking children")
                yield from self._parse_children_recursive(
                    col, item.get("name"), item.get("children")
                )
            else:
                if item.get("type") == "crypt":
                    logger.debug(
                        f"Found encrypted partition {item.get('name')} on {parent_device}"
                    )
                    mountpoint = item.get("mountpoint")
                    fstype = self._parse_fstype(
                        item.get("fstype")
                    )  # could be empty, vfat, ext4, etc. Note: the parent of a luks drive will show `crypto_LUKS` as its filesystem.
                    mapped_name = item.get("name")
                    encryption = self._parse_encryption(item.get("name"))  # todo
                    vol = Volume(
                        device_name=parent_device,
                        mapped_name=mapped_name,
                        encryption=encryption,
                    )
                    if mountpoint:
                        logger.error("yield mountedvolume")
                        collection.add(MountedVolume.from_volume(volume, mountpoint))
                    else:
                        logger.error(
                            f"yield volume: {vol.device_name}, {vol.mapped_name}"
                        )
                        collection.add(vol)
                else:
                    logger.debug("Not an encrypted volume")

    def get_all_volumes(self) -> List[Volume]:
        """
        Returns a list of all currently-attached removable Volumes that are
        export device candidates, attempting to get as far towards export process
        as possible (i.e. probing if device is already unlocked and/or mounted,
        and mounting it if unlocked but unmounted.)

        Caller must handle ExportException.
        """
        volumes = []
        removable_devices = self._get_connected_devices()
        try:
            for item in removable_devices:
                blkid = self._get_partitioned_device(item)
                if self.is_luks_volume(blkid):
                    logger.debug("LUKS volume detected. Checking if unlocked.")
                    volumes.append(self._get_luks_volume(blkid))
                else:
                    try:
                        logger.debug(
                            "Not a LUKS volume. Checking if unlocked VeraCrypt."
                        )
                        volumes.append(
                            self._attempt_get_unlocked_veracrypt_volume(blkid)
                        )
                    except ExportException:
                        logger.info("Device is not an unlocked Veracrypt drive.")
                        volumes.append(
                            Volume(
                                device_name=blkid,
                                encryption=EncryptionScheme.UNKNOWN,
                                # This will be the name we use if
                                # trying to unlock the drive.
                                mapped_name=self._DEFAULT_VC_CONTAINER_NAME,
                            )
                        )

            return volumes

        except ExportException as ex:
            logger.error(f"get_all_volumes failed: {ex.sdstatus.value}")
            logger.debug(ex)
            raise

    def is_luks_volume(self, device: str) -> bool:
        """
        Given a string representing a volume (/dev/sdX or /dev/sdX1), return True if volume is
        LUKS-encrypted, otherwise False.
        """
        isLuks = False

        try:
            logger.debug("Checking if target device is luks encrypted")

            # cryptsetup isLuks returns 0 if the device is a luks volume
            # subprocess will throw if the device is not luks (rc !=0)
            subprocess.check_call(["sudo", "cryptsetup", "isLuks", device])

            isLuks = True

        except subprocess.CalledProcessError:
            # Not necessarily an error state, just means the volume is not LUKS encrypted
            logger.info("Target device is not LUKS-encrypted")

        return isLuks

    def _get_luks_volume(self, device: str) -> Union[Volume, MountedVolume]:
        """
        Given a string corresponding to a LUKS-partitioned volume, return a corresponding Volume
        object.

        If LUKS volume is already mounted, existing mountpoint will be preserved and a
        MountedVolume object will be returned.
        If LUKS volume is unlocked but not mounted, volume will be mounted at _DEFAULT_MOUNTPOINT,
        and a MountedVolume object will be returned.

        If device is still locked, mountpoint will not be set, and a Volume object will be retuned.
        Once the decrpytion passphrase is available, call unlock_luks_volume(), passing the Volume
        object and passphrase to unlock the volume.

        Raise ExportException if errors are encountered.
        """
        try:
            mapped_name = self._get_luks_name_from_headers(device)
            logger.debug(f"Mapped name is {mapped_name}")

            # Setting the mapped_name does not mean the device has already been unlocked.
            luks_volume = Volume(
                device_name=device,
                mapped_name=mapped_name,
                encryption=EncryptionScheme.LUKS,
            )

            # If the device has been unlocked, we can see if it's mounted and
            # use the existing mountpoint, or mount it ourselves.
            # Either way, return a MountedVolume.
            if os.path.exists(os.path.join("/dev/mapper/", mapped_name)):
                return self.mount_volume(luks_volume)

            # It's still locked
            else:
                return luks_volume

        except ExportException:
            logger.error("Failed to return luks volume")
            raise

    def unlock_luks_volume(self, volume: Volume, decryption_key: str) -> Volume:
        """
        Unlock a LUKS-encrypted volume.

        Raise ExportException if errors are encountered during device unlocking.
        """
        if volume.encryption is not EncryptionScheme.LUKS:
            logger.error("Must call unlock_luks_volume() on LUKS-encrypted device")
            raise ExportException(sdstatus=Status.DEVICE_ERROR)

        try:
            logger.debug("Unlocking luks volume {}".format(volume.device_name))
            p = subprocess.Popen(
                [
                    "sudo",
                    "cryptsetup",
                    "luksOpen",
                    volume.device_name,
                    volume.mapped_name,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.debug("Passing key")
            p.communicate(input=str.encode(decryption_key, "utf-8"))
            rc = p.returncode

            if rc == 0:
                logger.debug("Successfully unlocked.")
                return volume
            else:
                logger.error("Bad volume passphrase")
                raise ExportException(sdstatus=Status.ERROR_UNLOCK_LUKS)

        except subprocess.CalledProcessError as ex:
            raise ExportException(sdstatus=Status.DEVICE_ERROR) from ex

    def _get_dev_mapper_entries(self) -> List[str]:
        """
        Helper function to return a list of entries in /dev/mapper/
        (excluding `system` and `dmroot`).
        """
        try:
            ls = subprocess.check_output(["ls", "/dev/mapper/"], stderr=subprocess.PIPE)
            entries = ls.decode("utf-8").rstrip().split("\n")

            return [r for r in entries if r not in _DEVMAPPER_SYSTEM]

        except (subprocess.CalledProcessError, ValueError) as ex:
            logger.error(f"Error checking entries in /dev/mapper: {ex}")
            raise ExportException(sdstatus=Status.DEVICE_ERROR) from ex

    def _attempt_get_unlocked_veracrypt_volume(self, device_name: str) -> MountedVolume:
        """
        Looks for an already-unlocked volume in /dev/mapper to see if the name matches
        given device name.
        Returns MountedVolume object if a drive is found. Otherwise, raises ExportException.
        """
        try:
            devmapper_entries = self._get_dev_mapper_entries()
            for item in devmapper_entries:
                # Check it out with cryptsetup, see if it's a VeraCrypt/TrueCrypt drive.
                # Example format (some lines ommitted for brevity):
                #
                # b'/dev/mapper/vc is active and is in use.\n  type:    TCRYPT\n  cipher:
                # aes-xts-plain64\n keysize: 512 bits\n  key location: dm-crypt\n  device:
                # /dev/sdc\n  sector size:  512\noffset:  256 sectors\n  size:
                # 1968640 sectors\n  skipped: 256 sectors\n  mode:    read/write\n'
                #
                # (A mapped entry can also have a null device, if it wasn't properly removed
                # from /dev/mapper using `cryptsetup close`.)
                status = (
                    subprocess.check_output(
                        ["sudo", "cryptsetup", "status", f"/dev/mapper/{item}"]
                    )
                    .decode("utf-8")
                    .split("\n  ")
                )

                logger.debug(f"{status}")

                if "type:    TCRYPT" in status and f"device:  {device_name}" in status:
                    logger.info("Unlocked VeraCrypt volume detected")
                    volume = Volume(
                        device_name=device_name,
                        mapped_name=item,
                        encryption=EncryptionScheme.VERACRYPT,
                    )

                    # Is it mounted?
                    mountpoint = (
                        subprocess.check_output(
                            [
                                "lsblk",
                                f"/dev/mapper/{item}",
                                "--noheadings",
                                "-o",
                                "MOUNTPOINT",
                            ]
                        )
                        .decode()
                        .strip()
                    )
                    if mountpoint:
                        # Note: Here we're accepting the user's choice of how they
                        # have mounted the drive, including whatever permissions/
                        # options they have set.
                        logger.info(f"Drive is already mounted at {mountpoint}")
                        return MountedVolume.from_volume(volume, mountpoint)
                    else:
                        logger.info(
                            "Drive is not mounted; mounting at default mountpoint"
                        )

                        # Fixme: we can't reliably use chown as we do with luks+ext4,
                        # since we don't know what filesystem is inside the veracrypt container.
                        return volume

                else:  # somehow it didn't work. dump the device info for now.
                    # fixme: this isn't necessarily. an error
                    logger.error(f"Did not parse veracrypt drive from: {status}")

            # If we got here, there is no unlocked VC drive present. Not an error, but not
            # a state we can continue the workflow in, so raise ExportException.
            logger.info("No unlocked Veracrypt drive found.")
            raise ExportException(sdstatus=Status.UNKNOWN_DEVICE_DETECTED)

        except subprocess.CalledProcessError as ex:
            logger.error("Encountered exception while checking /dev/mapper entries")
            logger.debug(ex)
            raise ExportException(sdstatus=Status.DEVICE_ERROR) from ex

    def attempt_unlock_veracrypt(
        self, volume: Volume, encryption_key: str
    ) -> MountedVolume:
        """
        Attempt to unlock and mount a presumed-Veracrypt drive at the default mountpoint.
        """
        try:
            p = subprocess.Popen(
                [
                    "sudo",
                    "cryptsetup",
                    "open",
                    "--type",
                    "tcrypt",
                    "--veracrypt",
                    f"{volume.device_name}",
                    f"{self._DEFAULT_VC_CONTAINER_NAME}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p.communicate(input=str.encode(encryption_key, "utf-8"))
            rc = p.returncode

            if rc == 0:
                volume.encryption = EncryptionScheme.VERACRYPT

                # Mapped name is /dev/mapper/${self._DEFAULT_VC_CONTAINER_NAME}, since
                # the /dev/mapper entry isn't derived from the header like a LUKS drive
                volume.mapped_name = self._DEFAULT_VC_CONTAINER_NAME
                return self.mount_volume(volume)

            else:
                # Something was wrong and we could not unlock.
                logger.error("Unlocking failed. Bad passphrase, or unsuitable volume.")
                raise ExportException(sdstatus=Status.ERROR_UNLOCK_GENERIC)

        except subprocess.CalledProcessError as error:
            logger.error("Error during unlock/mount attempt.")
            logger.debug(error)
            raise ExportException(sdstatus=Status.ERROR_UNLOCK_GENERIC)

    def _get_mountpoint(self, volume: Volume) -> Optional[str]:
        """
        Check for existing mountpoint.
        Raise ExportException if errors encountered during command.
        """
        logger.debug("Checking mountpoint")
        try:
            output = subprocess.check_output(
                ["lsblk", "-o", "MOUNTPOINT", "--noheadings", volume.device_name]
            )
            return output.decode("utf-8").strip()

        except subprocess.CalledProcessError as ex:
            logger.error(ex)
            raise ExportException(sdstatus=Status.ERROR_MOUNT) from ex

    def mount_volume(self, volume: Volume) -> MountedVolume:
        """
        Given an unlocked LUKS volume, return MountedVolume object.

        If volume is already mounted, mountpoint is not changed. Otherwise,
        volume is mounted at _DEFAULT_MOUNTPOINT.

        Raise ExportException if errors are encountered during mounting.
        """
        if not volume.unlocked:
            logger.error("Volume is not unlocked.")
            raise ExportException(sdstatus=Status.ERROR_MOUNT)

        mountpoint = self._get_mountpoint(volume)

        if mountpoint:
            logger.info("The device is already mounted--use existing mountpoint")
            return MountedVolume.from_volume(volume, mountpoint)

        else:
            logger.info("Mount volume at default mountpoint")
            return self._mount_at_mountpoint(volume, self._DEFAULT_MOUNTPOINT)

    def _mount_at_mountpoint(self, volume: Volume, mountpoint: str) -> MountedVolume:
        """
        Mount a volume at the supplied mountpoint, creating the mountpoint directory and
        adjusting permissions (user:user) if need be. `mountpoint` must be a full path.

        Return MountedVolume object.
        Raise ExportException if unable to mount volume at target mountpoint.
        """
        if not os.path.exists(mountpoint):
            try:
                subprocess.check_call(["sudo", "mkdir", mountpoint])
            except subprocess.CalledProcessError as ex:
                logger.error(ex)
                raise ExportException(sdstatus=Status.ERROR_MOUNT) from ex

        # Mount device /dev/mapper/{mapped_name} at /media/usb/
        mapped_device_path = os.path.join(
            volume.MAPPED_VOLUME_PREFIX, volume.mapped_name
        )

        try:
            logger.info(f"Mounting volume at {mountpoint}")
            subprocess.check_call(["sudo", "mount", mapped_device_path, mountpoint])
            subprocess.check_call(["sudo", "chown", "-R", "user:user", mountpoint])

            return MountedVolume.from_volume(volume, mountpoint)

        except subprocess.CalledProcessError as ex:
            logger.error(ex)
            raise ExportException(sdstatus=Status.ERROR_MOUNT) from ex

    def write_data_to_device(
        self,
        submission_tmpdir: str,
        submission_target_dirname: str,
        device: MountedVolume,
    ):
        """
        Move files to drive (overwrites files with same filename) and unmount drive.
        Drive is unmounted and files are cleaned up as part of the `finally` block to ensure
        that cleanup happens even if export fails or only partially succeeds.
        """

        try:
            target_path = os.path.join(device.mountpoint, submission_target_dirname)
            subprocess.check_call(["mkdir", target_path])

            export_data = os.path.join(submission_tmpdir, "export_data/")
            logger.debug("Copying file to {}".format(submission_target_dirname))

            subprocess.check_call(["cp", "-r", export_data, target_path])
            logger.info(
                "File copied successfully to {}".format(submission_target_dirname)
            )

        except (subprocess.CalledProcessError, OSError) as ex:
            logger.error(ex)
            raise ExportException(sdstatus=Status.ERROR_EXPORT) from ex

        finally:
            self.cleanup_drive_and_tmpdir(device, submission_tmpdir)

    def cleanup_drive_and_tmpdir(self, volume: MountedVolume, submission_tmpdir: str):
        """
        Post-export cleanup method. Unmount and lock drive and remove temporary
        directory. Currently called at end of `write_data_to_device()` to ensure
        device is always locked after export.

        Raise ExportException if errors during cleanup are encountered.
        """
        logger.debug("Syncing filesystems")
        try:
            subprocess.check_call(["sync"])
            umounted = self._unmount_volume(volume)
            if umounted:
                self._close_luks_volume(umounted)
            self._remove_temp_directory(submission_tmpdir)

        except subprocess.CalledProcessError as ex:
            logger.error("Error syncing filesystem")
            raise ExportException(sdstatus=Status.ERROR_EXPORT_CLEANUP) from ex

    def _unmount_volume(self, volume: MountedVolume) -> Volume:
        """
        Helper. Unmount volume
        """
        if os.path.exists(volume.mountpoint):
            logger.debug(f"Unmounting drive from {volume.mountpoint}")
            try:
                subprocess.check_call(["sudo", "umount", volume.mountpoint])

            except subprocess.CalledProcessError as ex:
                logger.error("Error unmounting device")
                raise ExportException(sdstatus=Status.DEVICE_ERROR) from ex
        else:
            logger.info("Mountpoint does not exist; volume was already unmounted")

        return Volume(
            device_name=volume.device_name,
            mapped_name=volume.mapped_name,
            encryption=volume.encryption,
        )

    def _close_luks_volume(self, unlocked_device: Volume) -> None:
        """
        Helper. Close LUKS volume
        """
        if os.path.exists(os.path.join("/dev/mapper", unlocked_device.mapped_name)):
            logger.debug("Locking luks volume {}".format(unlocked_device))
            try:
                subprocess.check_call(
                    ["sudo", "cryptsetup", "luksClose", unlocked_device.mapped_name]
                )

            except subprocess.CalledProcessError as ex:
                logger.error("Error closing device")
                raise ExportException(sdstatus=Status.DEVICE_ERROR) from ex

    def _close_veracrypt_volume(self, unlocked_device: MountedVolume) -> None:
        """
        Helper. Close VeraCrypt volume.
        """
        if os.path.exists(os.path.join("/dev/mapper", unlocked_device.mapped_name)):
            logger.debug("Locking luks volume {}".format(unlocked_device))
            try:
                subprocess.check_call(
                    ["sudo", "cryptsetup", "close", unlocked_device.mapped_name]
                )

            except subprocess.CalledProcessError as ex:
                logger.error("Error closing device")
                raise ExportException(sdstatus=Status.DEVICE_ERROR) from ex

    def _remove_temp_directory(self, tmpdir: str):
        """
        Helper. Remove temporary directory used during archive export.
        """
        logger.debug(f"Deleting temporary directory {tmpdir}")
        try:
            subprocess.check_call(["rm", "-rf", tmpdir])
        except subprocess.CalledProcessError as ex:
            logger.error("Error removing temporary directory")
            raise ExportException(sdstatus=Status.DEVICE_ERROR) from ex
