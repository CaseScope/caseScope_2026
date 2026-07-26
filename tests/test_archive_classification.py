"""Archive classification contract for CaseFile.is_zip_file()."""
import bz2
import gzip
import lzma
import os
import tarfile
import tempfile
import time
import unittest
import zipfile

os.environ.setdefault("SECRET_KEY", "test-secret")

from models.case_file import CaseFile

# Old code sent NUL-prefixed files through tarfile.is_tarfile(), which scanned
# them at roughly 8 MB/s; this sparse size took about 30s before the fix.
SPARSE_SIZE = 256 * 1024 * 1024
SPARSE_BUDGET_SECONDS = 5.0


class ArchiveClassificationTestCase(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.temp_root = self._temp.name
        self.addCleanup(self._temp.cleanup)

    def _path(self, name):
        return os.path.join(self.temp_root, name)

    def _write_tar(self, name, mode):
        payload = self._path("member.txt")
        with open(payload, "wb") as handle:
            handle.write(b"payload")
        archive_path = self._path(name)
        with tarfile.open(archive_path, mode) as archive:
            archive.add(payload, arcname="member.txt")
        return archive_path

    def test_large_nul_prefixed_file_is_not_an_archive(self):
        """A sparse NUL-prefixed artifact such as $UsnJrnl:$J must be rejected
        immediately instead of being scanned end to end."""
        sparse_path = self._path("usnjrnl.bin")
        with open(sparse_path, "wb") as handle:
            handle.truncate(SPARSE_SIZE)

        started = time.monotonic()
        result = CaseFile.is_zip_file(sparse_path)
        elapsed = time.monotonic() - started

        self.assertFalse(result)
        self.assertLess(elapsed, SPARSE_BUDGET_SECONDS)

    def test_zip_archive_is_detected(self):
        archive_path = self._path("collection.zip")
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("C/$MFT", b"data")

        self.assertTrue(CaseFile.is_zip_file(archive_path))

    def test_every_tar_flavor_is_detected(self):
        for fmt, name in (
            (tarfile.USTAR_FORMAT, "ustar.tar"),
            (tarfile.GNU_FORMAT, "gnu.tar"),
            (tarfile.PAX_FORMAT, "pax.tar"),
        ):
            with self.subTest(tar_format=name):
                payload = self._path("member.txt")
                with open(payload, "wb") as handle:
                    handle.write(b"payload")
                archive_path = self._path(name)
                with tarfile.open(archive_path, "w", format=fmt) as archive:
                    archive.add(payload, arcname="member.txt")
                self.assertTrue(CaseFile.is_zip_file(archive_path))

    def test_compressed_tarballs_are_detected(self):
        for mode, name in (("w:gz", "t.tar.gz"), ("w:bz2", "t.tar.bz2"), ("w:xz", "t.tar.xz")):
            with self.subTest(mode=mode):
                self.assertTrue(CaseFile.is_zip_file(self._write_tar(name, mode)))

    def test_compressed_non_tar_payloads_are_not_archives(self):
        cases = (
            ("plain.gz", gzip.compress(b"not a tar")),
            ("plain.bz2", bz2.compress(b"not a tar")),
            ("plain.xz", lzma.compress(b"not a tar")),
        )
        for name, blob in cases:
            with self.subTest(name=name):
                path = self._path(name)
                with open(path, "wb") as handle:
                    handle.write(blob)
                self.assertFalse(CaseFile.is_zip_file(path))

    def test_ordinary_artifacts_are_not_archives(self):
        cases = (
            ("notes.txt", b"hello world\n"),
            ("evtx.bin", b"ElfFile\x00" + b"\x00" * 600),
            ("empty.bin", b""),
        )
        for name, blob in cases:
            with self.subTest(name=name):
                path = self._path(name)
                with open(path, "wb") as handle:
                    handle.write(blob)
                self.assertFalse(CaseFile.is_zip_file(path))

    def test_missing_file_is_not_an_archive(self):
        self.assertFalse(CaseFile.is_zip_file(self._path("does-not-exist.zip")))


if __name__ == "__main__":
    unittest.main()
