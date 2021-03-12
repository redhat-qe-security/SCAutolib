from SCAutolib import log
import subprocess as subp


class Authselect:

    backup_name = "tmp.backup"

    def set(self, required=False, lock_on_removal=False, mk_homedir=False):
        args = ["authselect", "select", "sssd", "--backup", self.backup_name,
                "with-smartcard"]

        if required:
            args.append("with-smartcard-required")
        if lock_on_removal:
            args.append("with-smartcard-lock-on-removal")
        if mk_homedir:
            args.append("with-mkhomedir")
        args.append("--force")

        rc = subp.run(args,  stdout=subp.DEVNULL, stderr=subp.STDOUT)
        msg = f"Authselect command failed. Return code: {rc.returncode}"
        assert rc.returncode == 0, msg
        log.debug(f"SSSD is set to: {' '.join(args)}")
        log.debug(f"Backupfile: {self.backup_name}")

    def reset(self):
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
        return self

    def __exit__(self, type_, value, traceback):
        self.reset()
