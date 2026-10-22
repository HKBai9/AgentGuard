"""Exclusive local worker ownership, released by the OS after a process crash."""
from contextlib import contextmanager
from pathlib import Path
import os

from ..common import RuntimeFault


@contextmanager
def exclusive_worker(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Never unlink this file: replacing the inode would allow two owners.
    handle = (directory / 'worker.lock').open('a+b')
    acquired = False
    try:
        if os.name == 'nt':
            import msvcrt
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise RuntimeFault('RUNTIME_WORKER_ALREADY_RUNNING') from None
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RuntimeFault('RUNTIME_WORKER_ALREADY_RUNNING') from None
        acquired = True
        yield
    finally:
        if acquired:
            if os.name == 'nt':
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
