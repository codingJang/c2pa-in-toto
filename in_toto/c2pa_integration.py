# c2pa_integration.py

import logging
from typing import Dict, Any

from in_toto.models.metadata import Metadata
from in_toto.c2pa_utils import (
    load_c2pa_manifest,
    validate_c2pa_manifest,
    create_c2pa_signer
)
from c2pa import Builder

LOG = logging.getLogger(__name__)


class C2PAIntegration:
    """
    A class to handle C2PA metadata operations within the in-toto verification workflow.
    """

    def __init__(self, private_key_path: str, certs_path: str):
        """
        Initialize the C2PAIntegration with the necessary signer.

        Args:
            private_key_path (str): Path to the private key file used for signing C2PA manifests.
        """
        self.signer = create_c2pa_signer(private_key_path, certs_path)

    def read_c2pa_metadata(self, media_file: str) -> Dict[str, Any]:
        """
        Read and extract C2PA metadata from a media file.

        Args:
            media_file (str): Path to the media file.

        Returns:
            Dict[str, Any]: Extracted C2PA data.

        Raises:
            Exception: If metadata is missing or fails validation.
        """
        try:
            LOG.info(f"Reading C2PA metadata from {media_file}")
            c2pa_data = load_c2pa_manifest(media_file)
            if not validate_c2pa_manifest(c2pa_data):
                LOG.error("C2PA metadata validation failed.")
                raise Exception("C2PA metadata validation failed.")
            LOG.info("C2PA metadata read and validated successfully.")
            return c2pa_data

        except Exception as e:
            LOG.error(f"Failed to read C2PA metadata: {e}")
            raise e

    def embed_c2pa_metadata(
        self,
        media_file: str,
        manifest_data: Dict[str, Any],
        ingredient_file: str,
        resource_file: str,
        output_file: str
    ) -> None:
        """
        Embed a signed C2PA manifest into a media file.

        Args:
            media_file (str): Path to the original media file.
            manifest_data (Dict[str, Any]): Data defining the C2PA manifest.
            ingredient_file (str): Path to the ingredient file.
            resource_file (str): Path to the resource file (e.g., thumbnail).
            output_file (str): Path to the output media file with embedded C2PA metadata.

        Raises:
            Exception: If embedding fails.
        """
        try:
            LOG.info(f"Embedding C2PA metadata into {output_file}")

            # Initialize Builder with manifest definition
            builder = Builder(manifest_data)

            # Add resources
            builder.add_resource_file("thumbnail", resource_file)

            # Add ingredients
            ingredient_json = {
                "title": "A.jpg",
                "relationship": "parentOf",
                "thumbnail": {
                    "identifier": "thumbnail",
                    "format": "image/jpeg"
                }
            }
            builder.add_ingredient_file(ingredient_json, ingredient_file)

            # Sign and embed the manifest into the media file
            builder.sign_file(self.signer, media_file, output_file)

            LOG.info("C2PA metadata embedded and signed successfully.")

        except Exception as e:
            LOG.error(f"Failed to embed C2PA metadata: {e}")
            raise e

    def correlate_with_in_toto(
        self,
        c2pa_data: Dict[str, Any],
        in_toto_metadata_path: str
    ) -> bool:
        """
        Correlate C2PA claims with in-toto link metadata to ensure alignment.

        Args:
            c2pa_data (Dict[str, Any]): Extracted C2PA data.
            in_toto_metadata_path (str): Path to the in-toto link metadata file.

        Returns:
            bool: True if correlated successfully, False otherwise.
        """
        try:
            LOG.info(f"Correlating C2PA data with in-toto metadata from {in_toto_metadata_path}")
            in_toto_metadata = Metadata.load(in_toto_metadata_path).to_dict()

            # Example correlation logic:
            # Ensure that the title in C2PA matches the step name in in-toto metadata
            c2pa_title = c2pa_data.get("title", "")
            in_toto_step_name = in_toto_metadata.get("name", "")

            if c2pa_title != in_toto_step_name:
                LOG.error("Mismatch between C2PA title and in-toto step name.")
                return False

            # Additional correlation checks can be implemented here
            LOG.info("C2PA data and in-toto metadata are correlated successfully.")
            return True

        except Exception as e:
            LOG.error(f"Error during correlation: {e}")
            return False
