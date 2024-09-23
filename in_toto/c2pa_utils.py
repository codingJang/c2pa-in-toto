# c2pa_utils.py

import json
import logging
from typing import Dict, Any

from c2pa import Reader, Builder, create_signer, sign_ps256
from c2pa.c2pa import SigningAlg

LOG = logging.getLogger(__name__)


def load_c2pa_manifest(media_file: str) -> Dict[str, Any]:
    """
    Load and extract C2PA metadata from a media file.

    Args:
        media_file (str): Path to the media file containing C2PA metadata.

    Returns:
        Dict[str, Any]: Dictionary containing C2PA claims and statuses.

    Raises:
        FileNotFoundError: If the media file does not exist.
        Exception: If C2PA metadata is missing or fails validation.
    """
    try:
        LOG.info(f"Loading C2PA manifest from {media_file}")
        reader = Reader.from_file(media_file)
        manifest_store_json = reader.json()
        manifest_store = json.loads(manifest_store_json)
        LOG.debug(f"Manifest Store: {manifest_store}")

        active_manifest = reader.get_active_manifest()
        if not active_manifest:
            LOG.error("No active manifest found in the media file.")
            raise Exception("C2PA metadata is missing or no active manifest found.")

        # Extract relevant data from the active manifest
        c2pa_data = {
            "claim_generator_info": active_manifest.get("claim_generator_info", []),
            "title": active_manifest.get("title", ""),
            "thumbnail": active_manifest.get("thumbnail", {}),
            "assertions": active_manifest.get("assertions", [])
        }

        LOG.info("C2PA metadata loaded and extracted successfully.")
        return c2pa_data

    except FileNotFoundError:
        LOG.error(f"Media file not found: {media_file}")
        raise
    except json.JSONDecodeError:
        LOG.error("Failed to decode C2PA manifest JSON.")
        raise
    except Exception as e:
        LOG.error(f"Error loading C2PA manifest: {e}")
        raise


def validate_c2pa_manifest(c2pa_data: Dict[str, Any]) -> bool:
    """
    Validate the integrity and authenticity of the C2PA metadata.

    Args:
        c2pa_data (Dict[str, Any]): Extracted C2PA data.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        LOG.info("Validating C2PA manifest data.")
        # Implement specific validation logic as per C2PA standards
        # For example, check required fields are present
        required_fields = ["claim_generator_info", "title", "thumbnail", "assertions"]
        for field in required_fields:
            if field not in c2pa_data:
                LOG.error(f"Missing required field in C2PA data: {field}")
                return False

        # Additional validation can be added here (e.g., signature verification)
        LOG.info("C2PA manifest validation passed.")
        return True

    except Exception as e:
        LOG.error(f"Error during C2PA manifest validation: {e}")
        return False


def create_c2pa_signer(private_key_path: str, certs_path: str, signing_alg: int = SigningAlg.PS256) -> Any:
    """
    Create a C2PA signer using a private key.

    Args:
        private_key_path (str): Path to the private key file.
        signing_alg (str): Signing algorithm to use (default: "ps256").

    Returns:
        Any: Signer object to be used with Builder.

    Raises:
        FileNotFoundError: If the private key file does not exist.
        Exception: If signer creation fails.
    """
    try:
        LOG.info(f"Creating signer with private key: {private_key_path}")

        def private_sign(data: bytes) -> bytes:
            return sign_ps256(data, private_key_path)

        # Read public certificates (if needed)
        with open(certs_path, "rb") as cert_file:
            certs = cert_file.read()

        signer = create_signer(private_sign, signing_alg, certs, "http://timestamp.digicert.com")
        LOG.info("Signer created successfully.")
        return signer

    except FileNotFoundError:
        LOG.error(f"Private key file not found: {private_key_path}")
        raise
    except Exception as e:
        LOG.error(f"Error creating signer: {e}")
        raise
