import logging
import json
import os
import subprocess

from typing import List, Optional, Union

from securedrop_export.exceptions import ExportException

from .volume import EncryptionScheme, Volume, MountedVolume
from .status import Status

logger = logging.getLogger(__name__)


class CLI:
    """
    A Python wrapper for various shell commands required to detect, map, and
    mount Export devices.

    CLI callers must handle ExportException and all exceptions and exit with
    sys.exit(0) so that another program does not attempt to open the submission.
    """

    def get_volume(self) -> Volume:
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
                and item.get("rm") is True
                and item.get("ro") is False
            ]

            if len(removable_devices) == 0:
                raise ExportException(sdstatus=Status.NO_DEVICE_DETECTED)
            elif len(removable_devices) > 1:
                # For now we only support inserting one device at a time
                # during export. To support multi-device-select we would parse
                # these results as well
                raise ExportException(sdstatus=Status.MULTI_DEVICE_DETECTED)
            else:
                return self._parse_single_device(removable_devices[0])

        except subprocess.CalledProcessError:
            raise ExportException(sdstatus=Status.DEVICE_ERROR)

        except ExportException:
            raise

    def _parse_single_device(self, block_device: dict) -> Volume:
        """
        Given a JSON-formatted lsblk output for one device, determine if it
        is suitably partitioned and return Volume to be used for export.

        A device may have nested output, with the partitions appearing
        as 'children.' It would be possible to parse and accept a highly nested
        partition scheme, but for simplicity, accept only disks that have an
        encrypted partition at either the whole-device level or the first partition
        level.

         Acceptable disks:
          * Unlocked Veracrypt drives
          * Locked or unlocked LUKS drives
          * No more than one encrypted partition (multiple nonencrypted partitions
            are OK as they will be ignored).

        Returns Volume or throws ExportException.
        """
        volumes = []

        if "children" in block_device:
            for entry in block_device.get("children"):
                # /dev/sdX1, /dev/sdX2 etc
                if "children" in entry:
                    for partition in entry.get("children"):
                        volumes.append(self._get_volume_info(entry, partition))

                # /dev/sdX
                else:
                    volumes.append(self._get_volume_info(block_device, entry))

            if len(volumes) != 1:
                logger.error(f"Need one target on {block_device}, got {len(volumes)}")
                raise ExportException(sdstatus=Status.INVALID_DEVICE_DETECTED)
                return volumes[0]

        raise ExportException(sdstatus=Status.INVALID_DEVICE_DETECTED)

    def _get_volume_info(
        self, device, partition
    ) -> Optional[Union[Volume, MountedVolume]]:
        """
        Get eligible volume info.
        Will only return devices that are confirmed supported (meaning, LUKS drives
        or unlocked Veracrypt drives. Locked Veracrypt drives are excluded).
        """
        mapped_name = partition.get("name")
        device_name = device.get("name")
        mountpoint = device.get("mountpoint")

        if mountpoint is not None:
            encryption = self._get_cryptsetup_info(mountpoint)
            return MountedVolume(
                device_name=device_name,
                mapped_name=mapped_name,
                encryption=encryption,
                mountpoint=mountpoint,
            )

        elif partition.get("type") == "crypt" and device.get("fstype") == "crypto_LUKS":
            return Volume(
                device_name=device_name,
                mapped_name=mapped_name,
                encryption=EncryptionScheme.LUKS,
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

    # Not currently in use, since error-reporting and detection for locked Veracrypt
    # drives is cumbersome.
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
        volume is mounted in /media/user using udisksctl.

        Raise ExportException if errors are encountered during mounting.
        """
        if not volume.unlocked:
            logger.error("Volume is not unlocked.")
            raise ExportException(sdstatus=Status.ERROR_MOUNT)

        mountpoint = self._get_mountpoint(volume)

        if mountpoint:
            logger.info("The device is already mounted--use existing mountpoint")

        else:
            logger.info("Mount volume in /media/user")
            try:
                output = subprocess.check_output(
                    ["udisksctl", "mount", "-b", f"/dev/mapper/{volume.mapped_name}"]
                ).decode("utf-8")

                # Success is "Mounted $device at $mountpoint"
                if output.startswith("Mounted "):
                    mountpoint = output.split()[-1]
                else:
                    # it didn't successfully mount, but also exited with code 0?
                    raise ExportException(sdstatus=Status.ERROR_MOUNT)

            except subprocess.CalledProcessError as ex:
                logger.error(ex)
                raise ExportException(sdstatus=Status.ERROR_MOUNT) from ex

        return MountedVolume.from_volume(volume, mountpoint)

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
            unmounted = self._unmount_volume(volume)
            if umounted.encryption is EncryptionScheme.LUKS:
                self._close_luks_volume(unmounted)
            elif unmounted.encryption is EncryptionScheme.VERACRYPT:
                self._close_veracrypt_volume(unmounted)
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
                subprocess.check_call(["udisksctl", "unmount", volume.mountpoint])

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

    def _close_veracrypt_volume(self, unlocked_device: Volume) -> None:
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
