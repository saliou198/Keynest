from pathlib import Path

from .base import StorageBackend


class LocalStorage(StorageBackend):
    """Stores the vault as a local file on disk."""

    def __init__(self, path: str = "vault.enc"):
        self.path = Path(path)

    def upload(self, data: bytes) -> None:
        self.path.write_bytes(data)

    def download(self) -> bytes:
        return self.path.read_bytes()

    def exists(self) -> bool:
        return self.path.exists()
