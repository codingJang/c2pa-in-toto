# c2pa_resolver.py

import os
import subprocess
import json
import logging
import base64
from typing import Dict
from in_toto.resolver import Resolver
from in_toto.exceptions import PrefixError

logger = logging.getLogger(__name__)


class C2PAResolver(Resolver):
    """
    Resolver for C2PA manifests.

    Uses c2patool to extract the c2pa.hash.data assertion from media files.
    """

    SCHEME = "c2pa"

    def __init__(self, output_dir="./tests/temp/", lstrip_paths=None):
        if lstrip_paths is None:
            lstrip_paths = []

        self.output_dir = output_dir
        self._lstrip_paths = lstrip_paths

        # Ensure the output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def _strip_scheme_prefix(self, path):
        """Helper to strip c2pa resolver scheme prefix from path."""
        prefix = self.SCHEME + ":"
        if path.startswith(prefix):
            path = path[len(prefix):]
        else:
            prefix = ""
        return path, prefix

    def _mangle(self, path, existing_paths, scheme_prefix):
        """Helper for path mangling."""
        # Normalize slashes for cross-platform consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path):]
                break

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        # Prepend passed scheme prefix
        path = scheme_prefix + path

        return path

    def _extract_c2pa_hash(self, media_file):
        """
        Calls c2patool to extract the c2pa.hash.data assertion from the media file.

        Args:
            media_file (str): Path to the media file.

        Returns:
            str: The base64-encoded hash value from c2pa.hash.data.

        Raises:
            Exception: If c2patool fails or the assertion is missing.
        """
        detailed_report_path = os.path.join(self.output_dir, "detailed.json")

        # Build the c2patool command
        cmd = [
            "c2patool",
            media_file,
            "-d",
            "-f",
            "--output",
            self.output_dir
        ]

        # Call c2patool via subprocess
        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            logger.debug(f"c2patool output: {result.stdout}")
            if result.stderr:
                logger.warning(f"c2patool warnings: {result.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"c2patool failed for {media_file}: {e.stderr}")
            raise Exception(f"c2patool error: {e.stderr}")

        # Read the detailed.json output
        try:
            with open(detailed_report_path, "r", encoding="utf-8") as f:
                detailed_manifest = json.load(f)
        except FileNotFoundError:
            logger.error(f"Detailed manifest not found at {detailed_report_path}")
            raise Exception("Detailed manifest not found")

        # Extract the c2pa.hash.data assertion
        try:
            active_manifest_id = detailed_manifest["active_manifest"]
            manifests = detailed_manifest["manifests"]
            active_manifest = manifests[active_manifest_id]
            assertion_store = active_manifest["assertion_store"]
            c2pa_hash_data = assertion_store["c2pa.hash.data"]
            hash_value = c2pa_hash_data["hash"]
            return hash_value
        except KeyError as e:
            logger.error(f"Missing key in detailed manifest: {e}")
            raise Exception("c2pa.hash.data assertion not found")

    def hash_artifacts(self, uris):
        hashes = {}

        for uri in uris:
            # Remove scheme prefix, but preserve to re-add later (see _mangle)
            path, prefix = self._strip_scheme_prefix(uri)

            if not os.path.exists(path):
                logger.warning(f"File not found: {path}")
                continue

            try:
                hash_value = self._extract_c2pa_hash(path)
            except Exception as e:
                logger.error(f"Failed to extract c2pa.hash.data from {path}: {e}")
                continue

            # The hash_value is base64-encoded; decode it to get the binary hash
            try:
                hash_bytes = base64.b64decode(hash_value)
                hash_hex = hash_bytes.hex()
            except Exception as e:
                logger.error(f"Failed to decode hash value for {path}: {e}")
                continue

            # Use the algorithm specified in c2pa.hash.data (assuming SHA-256)
            algorithm = "sha256"  # Adjust if necessary

            name = self._mangle(path, hashes, prefix)
            hashes[name] = {algorithm: hash_hex}

        return hashes
