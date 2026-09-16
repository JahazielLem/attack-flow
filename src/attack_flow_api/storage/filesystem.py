from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


DEFAULT_ALLOWED_EXTENSIONS = {
    "txt",
    "json",
    "md",
    "pdf",
    "csv",
    "bin",
    "afb",
}


@dataclass(slots=True)
class StoredFile:
    storage_type: str
    filename: str
    relative_path: str
    absolute_path: Path
    size_bytes: int


class LocalFileStorage:
    def __init__(
        self,
        data_dir: Path,
        upload_dir: Path,
        artifact_dir: Path,
        strict_mode: bool = True,
        max_file_size_bytes: int | None = None,
    ):
        self.data_dir = data_dir.resolve()
        self.upload_dir = upload_dir.resolve()
        self.artifact_dir = artifact_dir.resolve()
        self.normalized_dir = (self.data_dir / "normalized").resolve()
        self.strict_mode = strict_mode
        self.max_file_size_bytes = max_file_size_bytes
        self._validate_storage_roots()
        self.ensure_directories()

    def _validate_storage_roots(self) -> None:
        for root in (self.upload_dir, self.artifact_dir, self.normalized_dir):
            if not self._is_within_base(root, self.data_dir):
                raise ValueError("Storage directories must be within DATA_DIR")

    def ensure_directories(self) -> None:
        for directory in (self.data_dir, self.upload_dir, self.artifact_dir, self.normalized_dir):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)

    def write_upload(self, content: bytes, extension: str | None = None) -> StoredFile:
        return self._write(content=content, storage_type="upload", extension=extension)

    def write_artifact(self, content: bytes, extension: str | None = None) -> StoredFile:
        return self._write(content=content, storage_type="artifact", extension=extension)

    def write_normalized(self, content: bytes, extension: str | None = None) -> StoredFile:
        return self._write(content=content, storage_type="normalized", extension=extension)

    def read_bytes(self, relative_path: str) -> bytes:
        file_path = self.resolve_stored_path(relative_path)
        return file_path.read_bytes()

    def delete_stored_file(self, relative_path: str) -> bool:
        file_path = self.resolve_stored_path(relative_path)
        if not file_path.exists():
            return False
        if file_path.is_dir():
            raise ValueError("Refusing to delete directory path")
        file_path.unlink()
        return True

    def resolve_stored_path(self, relative_path: str) -> Path:
        candidate = (self.data_dir / relative_path).resolve()
        if not self._is_within_data_dir(candidate):
            raise ValueError("Resolved path escapes data directory")
        if self.strict_mode and candidate.is_symlink():
            raise ValueError("Resolved path cannot be a symlink")
        return candidate

    def _write(self, content: bytes, storage_type: str, extension: str | None = None) -> StoredFile:
        if self.max_file_size_bytes is not None and len(content) > self.max_file_size_bytes:
            raise ValueError("File content exceeds configured maximum size")

        base_dir = self._base_dir_for_type(storage_type)
        filename = self._generate_filename(extension)
        dated_dir = Path(datetime.now(UTC).strftime("%Y/%m/%d"))
        absolute_path = (base_dir / dated_dir / filename).resolve()

        if not self._is_within_base(absolute_path, base_dir):
            raise ValueError("Resolved path escapes storage directory")
        if self.strict_mode:
            self._validate_symlink_chain(absolute_path.parent)
            if absolute_path.exists() and absolute_path.is_symlink():
                raise ValueError("Refusing to write through symlink path")

        absolute_path.parent.mkdir(parents=True, exist_ok=True)
        absolute_path.parent.chmod(0o700)
        absolute_path.write_bytes(content)
        absolute_path.chmod(0o600)
        relative_path = absolute_path.relative_to(self.data_dir)

        return StoredFile(
            storage_type=storage_type,
            filename=filename,
            relative_path=str(relative_path),
            absolute_path=absolute_path,
            size_bytes=len(content),
        )

    def _base_dir_for_type(self, storage_type: str) -> Path:
        if storage_type == "upload":
            return self.upload_dir
        if storage_type == "artifact":
            return self.artifact_dir
        if storage_type == "normalized":
            return self.normalized_dir
        raise ValueError(f"Unsupported storage type: {storage_type}")

    def _generate_filename(self, extension: str | None = None) -> str:
        normalized_extension = self._normalize_extension(extension)
        return f"{uuid4().hex}{normalized_extension}"

    def _normalize_extension(self, extension: str | None) -> str:
        if extension is None:
            return ""

        candidate = extension.strip().lower()
        if not candidate:
            return ""

        if candidate.startswith("."):
            candidate = candidate[1:]

        if len(candidate) > 10 or not candidate.isalnum():
            return self._handle_invalid_extension(extension)
        if candidate not in DEFAULT_ALLOWED_EXTENSIONS:
            return self._handle_invalid_extension(extension)
        return f".{candidate}"

    def _handle_invalid_extension(self, extension: str) -> str:
        if self.strict_mode:
            raise ValueError(f"Unsupported file extension: {extension}")
        return ".bin"

    def _validate_symlink_chain(self, directory: Path) -> None:
        current = directory
        while current != self.data_dir:
            if current.is_symlink():
                raise ValueError("Refusing to use symlinked storage directories")
            current = current.parent
        if self.data_dir.is_symlink():
            raise ValueError("Refusing to use symlinked data directory")

    def _is_within_data_dir(self, path: Path) -> bool:
        return self._is_within_base(path, self.data_dir)

    def _is_within_base(self, path: Path, base: Path) -> bool:
        try:
            path.relative_to(base)
        except ValueError:
            return False
        return True
