#!/usr/bin/env python3
"""
Example usage of C2PA integration with in-toto ITE-7 X.509 certificate support.

This script demonstrates:
1. Creating test certificates for X.509 signing
2. Embedding C2PA metadata with X.509 certificate information
3. Reading and validating C2PA metadata with certificate verification
4. Correlating C2PA data with in-toto link metadata
5. Certificate chain verification

This example implements the workflow described in ITE-7 for X.509 certificate
signing and verification in the context of C2PA integration.
"""

import os
import tempfile
import shutil
import json
import logging
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from in_toto.c2pa_integration import C2PAIntegration
from in_toto.c2pa_utils import load_x509_certificate, extract_certificate_info
from in_toto.models.metadata import Metadata

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
LOG = logging.getLogger(__name__)


class ITE7C2PAExample:
    """Example implementation of C2PA with ITE-7 X.509 certificate support."""

    def __init__(self):
        """Initialize the example with temporary directories."""
        self.work_dir = tempfile.mkdtemp(prefix="c2pa_ite7_")
        self.private_key_path = os.path.join(self.work_dir, "signing_key.pem")
        self.cert_path = os.path.join(self.work_dir, "signing_cert.pem")
        self.ca_cert_path = os.path.join(self.work_dir, "ca_cert.pem")
        self.media_file = os.path.join(self.work_dir, "original_media.jpg")
        self.signed_media = os.path.join(self.work_dir, "signed_media.jpg")
        self.in_toto_metadata = os.path.join(self.work_dir, "link_metadata.link")

        LOG.info(f"Working directory: {self.work_dir}")

    def cleanup(self):
        """Clean up temporary files."""
        shutil.rmtree(self.work_dir)
        LOG.info("Cleanup completed")

    def create_test_certificates(self):
        """Create test X.509 certificates for ITE-7 demonstration."""
        LOG.info("Creating test X.509 certificates for ITE-7 demonstration")

        # Generate CA private key
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create CA certificate
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITE-7 Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ITE-7 Test Root CA"),
        ])

        ca_cert = x509.CertificateBuilder().subject_name(
            ca_subject
        ).issuer_name(
            ca_subject  # Self-signed
        ).public_key(
            ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(ca_private_key, hashes.SHA256())

        # Save CA certificate
        with open(self.ca_cert_path, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        # Generate signing private key
        signing_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Save signing private key
        with open(self.private_key_path, 'wb') as f:
            f.write(signing_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Create signing certificate
        signing_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITE-7 Test Organization"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "C2PA Signing"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ite7-c2pa-signer.example.com"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "signer@example.com"),
        ])

        signing_cert = x509.CertificateBuilder().subject_name(
            signing_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            signing_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ]),
            critical=True,
        ).sign(ca_private_key, hashes.SHA256())

        # Save signing certificate
        with open(self.cert_path, 'wb') as f:
            f.write(signing_cert.public_bytes(serialization.Encoding.PEM))

        LOG.info("X.509 certificates created successfully")

        # Display certificate information
        cert_info = extract_certificate_info(signing_cert)
        LOG.info(f"Signing certificate subject: {cert_info.get('subject', {})}")
        LOG.info(f"Certificate serial number: {cert_info.get('serial_number')}")

    def create_test_media(self):
        """Create a test media file for demonstration."""
        LOG.info("Creating test media file")

        # Create a minimal JPEG-like file
        jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
        jpeg_data = b'\x00' * 2000  # Some dummy image data
        jpeg_end = b'\xff\xd9'

        with open(self.media_file, 'wb') as f:
            f.write(jpeg_header + jpeg_data + jpeg_end)

        LOG.info(f"Test media file created: {self.media_file}")

    def create_in_toto_metadata(self):
        """Create sample in-toto link metadata for correlation testing."""
        LOG.info("Creating sample in-toto link metadata")

        # Create a simple link metadata file
        link_data = {
            "_type": "link",
            "name": "c2pa-signing-step",
            "materials": {},
            "products": {
                "signed_media.jpg": {
                    "sha256": "dummy_hash_for_example"
                }
            },
            "command": ["c2pa-sign", "--input", "original_media.jpg", "--output", "signed_media.jpg"],
            "environment": {
                "c2pa_version": "1.0",
                "ite7_support": "enabled"
            }
        }

        with open(self.in_toto_metadata, 'w') as f:
            json.dump(link_data, f, indent=2)

        LOG.info(f"in-toto metadata created: {self.in_toto_metadata}")

    def demonstrate_ite7_workflow(self):
        """Demonstrate the complete ITE-7 workflow with C2PA integration."""
        LOG.info("=== Starting ITE-7 C2PA Integration Demonstration ===")

        # Step 1: Initialize C2PA integration with X.509 certificates
        LOG.info("Step 1: Initializing C2PA integration with X.509 certificates")
        c2pa_integration = C2PAIntegration(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )

        # Display certificate information
        cert_info = c2pa_integration.get_certificate_info()
        LOG.info(f"Loaded certificate with subject: {cert_info.get('subject', {})}")

        # Step 2: Verify certificate chain (ITE-7 requirement)
        LOG.info("Step 2: Verifying X.509 certificate chain")
        cert_valid = c2pa_integration.verify_certificate_chain(self.cert_path)
        if cert_valid:
            LOG.info("✓ Certificate chain verification passed")
        else:
            LOG.error("✗ Certificate chain verification failed")
            return False

        # Step 3: Embed C2PA metadata with X.509 certificate information
        LOG.info("Step 3: Embedding C2PA metadata with X.509 certificate information")
        manifest_data = {
            "claim_generator_info": [{
                "name": "ITE-7-C2PA-Example",
                "version": "1.0.0"
            }],
            "title": "ITE-7 X.509 Signed Media Example",
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
                },
                {
                    "label": "c2pa.ite7.certificate",
                    "data": {
                        "certificate_subject": cert_info.get('subject', {}),
                        "certificate_serial": cert_info.get('serial_number'),
                        "signature_algorithm": cert_info.get('signature_algorithm'),
                        "validity_period": {
                            "not_before": cert_info.get('not_valid_before'),
                            "not_after": cert_info.get('not_valid_after')
                        }
                    }
                }
            ]
        }

        try:
            c2pa_integration.embed_c2pa_metadata(
                media_file=self.media_file,
                manifest_data=manifest_data,
                ingredient_file=self.media_file,
                resource_file=self.media_file,
                output_file=self.signed_media
            )
            LOG.info("✓ C2PA metadata embedded successfully")
        except Exception as e:
            LOG.error(f"✗ Failed to embed C2PA metadata: {e}")
            return False

        # Step 4: Read and validate C2PA metadata with X.509 verification
        LOG.info("Step 4: Reading and validating C2PA metadata with X.509 verification")
        try:
            c2pa_data = c2pa_integration.read_c2pa_metadata(self.signed_media)
            LOG.info("✓ C2PA metadata read successfully")

            # Check X.509 verification result
            x509_verification = c2pa_data.get("x509_verification", False)
            if x509_verification:
                LOG.info("✓ X.509 certificate verification passed")
            else:
                LOG.warning("⚠ X.509 certificate verification result not available")

        except Exception as e:
            LOG.error(f"✗ Failed to read C2PA metadata: {e}")
            return False

        # Step 5: Correlate C2PA data with in-toto metadata (ITE-7 integration)
        LOG.info("Step 5: Correlating C2PA data with in-toto metadata")
        try:
            correlation_result = c2pa_integration.correlate_with_in_toto(
                c2pa_data, self.in_toto_metadata
            )
            if correlation_result:
                LOG.info("✓ C2PA and in-toto metadata correlation successful")
            else:
                LOG.warning("⚠ C2PA and in-toto metadata correlation failed")
        except Exception as e:
            LOG.error(f"✗ Correlation error: {e}")

        LOG.info("=== ITE-7 C2PA Integration Demonstration Complete ===")
        return True

    def run_example(self):
        """Run the complete ITE-7 example."""
        try:
            # Setup
            self.create_test_certificates()
            self.create_test_media()
            self.create_in_toto_metadata()

            # Run demonstration
            success = self.demonstrate_ite7_workflow()

            if success:
                LOG.info("🎉 ITE-7 C2PA integration example completed successfully!")
                LOG.info(f"Files created in: {self.work_dir}")
                LOG.info("You can examine the generated certificates and signed media file.")
            else:
                LOG.error("❌ ITE-7 C2PA integration example failed")

        except Exception as e:
            LOG.error(f"Example execution failed: {e}")
        finally:
            # Cleanup (comment out to keep files for inspection)
            # self.cleanup()
            pass


def main():
    """Main entry point for the example."""
    print("ITE-7 C2PA Integration Example")
    print("=" * 50)
    print("This example demonstrates X.509 certificate-based")
    print("signing and verification with C2PA integration as")
    print("specified in in-toto Enhancement 7 (ITE-7).")
    print()

    example = ITE7C2PAExample()
    example.run_example()


if __name__ == "__main__":
    main()