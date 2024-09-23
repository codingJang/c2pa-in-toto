# example_usage.py

import logging
import os
from in_toto.c2pa_integration import C2PAIntegration


# Configure logging
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
os.environ["RUST_LOG"] = "debug"


def main():
    # Paths to necessary files
    original_media = "images/original_media.jpg"
    ingredient_file = "images/A.jpg"
    resource_file = "images/A_thumbnail.jpg"
    output_media = "images/signed_media.jpg"
    in_toto_metadata = "images/link_metadata.link"

    # Initialize C2PAIntegration with the path to the private key
    private_key_path = "tests/fixtures/SelfCert.key"
    certs_path = "tests/fixtures/SelfCert-sign.pem"
    c2pa_integration = C2PAIntegration(private_key_path, certs_path)

    try:
        # Embed C2PA metadata into the media file
        manifest_data = {
            "claim_generator_info": [{
                "name": "python_test",
                "version": "0.1"
            }],
            "title": "Do Not Train Example",
            "thumbnail": {
                "format": "image/jpeg",
                "identifier": "thumbnail"
            },
            "assertions": [
                {
                    "label": "c2pa.training-mining",
                    "data": {
                        "entries": {
                            "c2pa.ai_generative_training": {"use": "notAllowed"},
                            "c2pa.ai_inference": {"use": "notAllowed"},
                            "c2pa.ai_training": {"use": "notAllowed"},
                            "c2pa.data_mining": {"use": "notAllowed"}
                        }
                    }
                }
            ]
        }

        c2pa_integration.embed_c2pa_metadata(
            media_file=original_media,
            manifest_data=manifest_data,
            ingredient_file=ingredient_file,
            resource_file=resource_file,
            output_file=output_media
        )

        LOG.info("C2PA metadata embedded successfully.")

        # Read and validate C2PA metadata from the signed media
        c2pa_data = c2pa_integration.read_c2pa_metadata(output_media)

        # Correlate C2PA data with in-toto metadata
        correlation_result = c2pa_integration.correlate_with_in_toto(c2pa_data, in_toto_metadata)

        if correlation_result:
            LOG.info("C2PA metadata successfully correlated with in-toto metadata.")
        else:
            LOG.error("C2PA and in-toto metadata correlation failed.")

    except Exception as e:
        LOG.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
