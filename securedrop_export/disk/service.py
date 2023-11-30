import logging

from .cli import CLI
from .status import Status
from .volume import Volume, MountedVolume, EncryptionScheme
from securedrop_export.archive import Archive
from securedrop_export.exceptions import ExportException
from typing import List, Optional, Tuple


logger = logging.getLogger(__name__)


class Service:
    """
    Actions that can be performed against USB device(s).
    This is the "API" portion of the export workflow.
    """

    def __init__(self, submission: Archive, cli: CLI = CLI()):
        self.cli = cli
        self.submission = submission

    def scan_all_devices(self) -> Status:
        """
        Check all connected devices and return export status.
        """
        try:
            volume = self.cli.get_volume()

            if volume.unlocked:
                return Status.DEVICE_WRITABLE
            else:
                return Status.DEVICE_LOCKED

        except ExportException as ex:
            logger.error(ex)
            return ex.sdstatus if ex.sdstatus is not None else Status.DEVICE_ERROR

    def export(self) -> Status:
        """
        Export material to USB drive.
        """
        try:
            volume = self.cli.get_volume()

            # If it's writable, it's a MountedVolume object
            if status == Status.DEVICE_WRITABLE and isinstance(target, MountedVolume):
                return self._write_to_device(target, self.submission)
            elif status == Status.DEVICE_LOCKED:
                status, unlocked_volume = self._unlock_device(
                    self.submission.encryption_key, target
                )
                if status == Status.DEVICE_WRITABLE and isinstance(
                    target, MountedVolume
                ):
                    return self._write_to_device(target, self.submission)
                else:
                    return status
            else:
                logger.info(f"Could not export, volume check was {status.value}")
                return status

        except ExportException as ex:
            logger.debug(ex)
            status = ex.sdstatus if ex.sdstatus is not None else Status.ERROR_EXPORT
            logger.error(f"Enountered {status.value} while trying to export")
            return status

    def _unlock_device(
        self, passphrase: str, volume: Volume
    ) -> Tuple[Status, Optional[Volume]]:
        """
        Given provided passphrase, unlock target volume.
        """

        if volume.encryption is EncryptionScheme.LUKS:
            try:
                logger.info("Unlocking LUKS drive")
                volume = self.cli.unlock_luks_volume(volume, passphrase)
                if volume.unlocked:
                    logger.debug("Volume unlocked, attempt to mount")
                    # Returns MountedVolume or errors
                    return (Status.DEVICE_WRITABLE, self.cli.mount_volume(volume))
            except ExportException as ex:
                logger.error(ex)

            return (Status.ERROR_UNLOCK_LUKS, volume)

        # Try to unlock another drive, opportunistically
        # hoping it is VeraCrypt/TC.
        # Note: We have not implemented error-handling for locked VeraCrypt drives,
        # so for now this is not in use.
        #
        # else:
        #     try:
        #         logger.info(
        #             "Encryption scheme is not LUKS. Attempt VeraCrypt unlock."
        #         )
        #         volume = self.cli.attempt_unlock_veracrypt(volume, passphrase)

        #         if isinstance(volume, MountedVolume):
        #             return (Status.DEVICE_WRITABLE, volume)
        #         else:
        #             # Might be VeraCrypt, might be madness
        #             return (Status.ERROR_UNLOCK_GENERIC, volume)
        #     except ExportException as ex:
        #         logger.error(ex)
        #         return (Status.ERROR_UNLOCK_GENERIC, volume)

    def _write_to_device(self, volume: MountedVolume, data: Archive) -> Status:
        """
        Export data to volume. CLI unmounts and locks volume on completion, even
        if export was unsuccessful.

        Calling method should handle ExportException.
        """
        self.cli.write_data_to_device(data.tmpdir, data.target_dirname, volume)
        return Status.SUCCESS_EXPORT
