from SCAutolib import log
import subprocess as subp


class Authselect:

    backup_name = "tmp.backup"

    def __init__(self, required=False, lock_on_removal=False, mk_homedir=False):
        """
        Construcotr for Authselect class. By default only with-smartcard option
        is used. When setting the SSSD profile, also --force is used. Previous
        configuration would be store into backup file and restored on exiting
        the context manager.

        Args:
            required: specifies with-smartcard-required option
            lock_on_removal: specifies with-smartcard-lock-on-removal option
            mk_homedir: specifies with-mkhomedir option
        """
        self._required = required
        self._lock_on_removal = lock_on_removal
        self._mk_homedir = mk_homedir

    def _set(self):
        """
        Set authselect with SSSD profile and use given options. Options are
        passed into the constructor.
        """
        args = ["authselect", "select", "sssd", "--backup", self.backup_name,
                "with-smartcard"]

        if self._required:
            args.append("with-smartcard-required")
        if self._lock_on_removal:
            args.append("with-smartcard-lock-on-removal")
        if self._mk_homedir:
            args.append("with-mkhomedir")
        args.append("--force")

        rc = subp.run(args,  stdout=subp.DEVNULL, stderr=subp.STDOUT)
        msg = f"Authselect command failed. Return code: {rc.returncode}"
        assert rc.returncode == 0, msg
        log.debug(f"SSSD is set to: {' '.join(args)}")
        log.debug(f"Backupfile: {self.backup_name}")

    def _reset(self):
        """
        Restore the previous configuration of authselect.
        """
        rc = subp.run(["authselect", "backup-restore", self.backup_name,
                       "--debug"], stdout=subp.DEVNULL, stderr=subp.STDOUT)
        msg = f"Authselect backup-restore failed. Output: {rc.returncode}"
        assert rc.returncode == 0, msg

        rc = subp.run(["authselect", "backup-remove", self.backup_name,
                       "--debug"], stdout=subp.DEVNULL, stderr=subp.STDOUT)
        msg = f"Authselect backup-remove failed. Output: {rc.returncode}"
        assert rc.returncode == 0, msg

        log.debug("Authselect backup file is restored")

    def __enter__(self):
        self._set()
        return self

    def __exit__(self, ext_type, ext_value, ext_traceback):
        if ext_type is not None:
            log.error("Exception in virtual smart card context")
            log.error(f"Exception type: {ext_type}")
            log.error(f"Exception value: {ext_value}")
            log.error(f"Exception traceback: {ext_traceback}")
        self._reset()
