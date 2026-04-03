"""Utility helpers v3.0"""

import hashlib
import os
import platform


def file_hash(filepath: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_data_dir() -> str:
    """Get a writable directory for logs/reports, favoring the real user's home."""
    # When running with sudo, ~ usually points to /root.
    # We want to use the home directory of the actual user who ran sudo.
    real_user = os.environ.get("SUDO_USER")
    if real_user and platform.system() != "Windows":
        import pwd
        home_dir = os.path.expanduser(f"~{real_user}")
    else:
        home_dir = os.path.expanduser("~")

    candidates = [
        os.path.join(home_dir, ".keyshield"),
        os.path.join(os.getcwd(), "keyshield_data"),
    ]
    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
            # If we are root, we need to ensure the real user can write to this dir
            if real_user and os.getuid() == 0:
                import pwd, grp
                user_info = pwd.getpwnam(real_user)
                os.chown(d, user_info.pw_uid, user_info.pw_gid)
            return d
        except OSError:
            continue
    return os.getcwd()


def secure_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    # Remove any path separators and dangerous characters
    for ch in ("/", "\\", "..", "~", "\x00"):
        filename = filename.replace(ch, "")
    return filename or "unnamed"
