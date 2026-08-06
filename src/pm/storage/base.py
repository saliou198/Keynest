from abc import ABC, abstractmethod


class StorageBackend(ABC):
    """Abstract interface for vault storage backends.

    Every backend must know how to upload, download, and check
    existence of the vault data. The data is opaque bytes — the
    backend never knows about encryption, JSON format, or passwords.
    """

    @abstractmethod
    def upload(self, data: bytes) -> None:
        """Store the vault data (overwrites existing)."""
        ...

    @abstractmethod
    def download(self) -> bytes:
        """Retrieve the vault data. Raises if no vault exists."""
        ...

    @abstractmethod
    def exists(self) -> bool:
        """Return True if a vault is stored on this backend."""
        ...
