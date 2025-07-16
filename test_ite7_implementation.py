#!/usr/bin/env python3
"""
Comprehensive test script for ITE-7 C2PA integration implementation.

This script tests the complete ITE-7 workflow including:
1. X.509 certificate generation and validation
2. C2PA metadata operations with certificate support
3. Certificate chain verification
4. Correlation with in-toto metadata
5. Error handling and edge cases
"""

import os
import sys
import tempfile
import shutil
import json
import logging
from datetime import datetime, timedelta

# Add workspace to Python path
sys.path.insert(0, '/workspace')

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from in_toto.c2pa_integration_test import C2PAIntegrationTest
from in_toto.c2pa_utils_test import (
    load_x509_certificate, 
    extract_certificate_info,
    validate_x509_certificate_chain
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)


class ITE7TestSuite:
    """Test suite for ITE-7 C2PA integration."""

    def __init__(self):
        """Initialize test suite with temporary workspace."""
        self.test_dir = tempfile.mkdtemp(prefix="ite7_test_")
        self.private_key_path = os.path.join(self.test_dir, "signing_key.pem")
        self.cert_path = os.path.join(self.test_dir, "signing_cert.pem")
        self.ca_cert_path = os.path.join(self.test_dir, "ca_cert.pem")
        self.media_file = os.path.join(self.test_dir, "test_media.jpg")
        self.signed_media = os.path.join(self.test_dir, "signed_media.jpg")
        self.in_toto_metadata = os.path.join(self.test_dir, "metadata.link")
        
        self.test_results = []
        
        LOG.info(f"Test workspace: {self.test_dir}")

    def cleanup(self):
        """Clean up test workspace."""
        try:
            shutil.rmtree(self.test_dir)
            LOG.info("Test workspace cleaned up")
        except Exception as e:
            LOG.warning(f"Failed to cleanup test workspace: {e}")

    def run_test(self, test_name: str, test_func):
        """Run a single test and record result."""
        LOG.info(f"Running test: {test_name}")
        try:
            test_func()
            self.test_results.append((test_name, "PASS", None))
            LOG.info(f"✅ {test_name}: PASSED")
            return True
        except Exception as e:
            self.test_results.append((test_name, "FAIL", str(e)))
            LOG.error(f"❌ {test_name}: FAILED - {e}")
            return False

    def test_certificate_generation(self):
        """Test X.509 certificate generation."""
        # Generate CA private key
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create CA certificate
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITE-7 Test CA"),
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
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
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
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITE-7 Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ite7-test-signer.example.com"),
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
        ).sign(ca_private_key, hashes.SHA256())

        # Save signing certificate
        with open(self.cert_path, 'wb') as f:
            f.write(signing_cert.public_bytes(serialization.Encoding.PEM))

        # Verify files exist
        assert os.path.exists(self.private_key_path), "Private key file not created"
        assert os.path.exists(self.cert_path), "Certificate file not created"
        assert os.path.exists(self.ca_cert_path), "CA certificate file not created"
        
        LOG.info("X.509 certificates generated successfully")

    def test_certificate_loading(self):
        """Test X.509 certificate loading and information extraction."""
        # Load certificate
        cert = load_x509_certificate(self.cert_path)
        assert isinstance(cert, x509.Certificate), "Failed to load certificate"

        # Extract certificate information
        cert_info = extract_certificate_info(cert)
        assert isinstance(cert_info, dict), "Failed to extract certificate info"
        assert "subject" in cert_info, "Subject missing from certificate info"
        assert "issuer" in cert_info, "Issuer missing from certificate info"
        assert "serial_number" in cert_info, "Serial number missing from certificate info"
        
        LOG.info(f"Certificate info extracted: {cert_info['subject']}")

    def test_certificate_chain_validation(self):
        """Test X.509 certificate chain validation."""
        # Load certificates
        signing_cert = load_x509_certificate(self.cert_path)
        ca_cert = load_x509_certificate(self.ca_cert_path)

        # Test single certificate validation
        result = validate_x509_certificate_chain([signing_cert])
        assert result, "Single certificate validation failed"

        # Test certificate chain validation
        result = validate_x509_certificate_chain([signing_cert, ca_cert])
        assert result, "Certificate chain validation failed"

        # Test with trusted CA
        result = validate_x509_certificate_chain([signing_cert], ca_cert)
        assert result, "Trusted CA validation failed"
        
        LOG.info("Certificate chain validation tests passed")

    def test_media_file_creation(self):
        """Test creation of test media file."""
        # Create a minimal JPEG-like file
        jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
        jpeg_data = b'\x00' * 1000
        jpeg_end = b'\xff\xd9'

        with open(self.media_file, 'wb') as f:
            f.write(jpeg_header + jpeg_data + jpeg_end)

        assert os.path.exists(self.media_file), "Test media file not created"
        assert os.path.getsize(self.media_file) > 0, "Test media file is empty"
        
        LOG.info(f"Test media file created: {self.media_file}")

    def test_c2pa_integration_initialization(self):
        """Test C2PA integration initialization with X.509 certificates."""
        integration = C2PAIntegrationTest(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )

        assert integration.signer is not None, "Signer not created"
        assert integration.trusted_ca_cert is not None, "Trusted CA not loaded"
        assert integration.signing_cert is not None, "Signing certificate not loaded"
        assert isinstance(integration.signing_cert_info, dict), "Certificate info not extracted"
        
        LOG.info("C2PA integration initialized successfully")

    def test_c2pa_metadata_embedding(self):
        """Test C2PA metadata embedding with X.509 certificate information."""
        integration = C2PAIntegrationTest(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )

        manifest_data = {
            "claim_generator_info": [{"name": "ITE-7-Test", "version": "1.0.0"}],
            "title": "ITE-7 Test Media",
            "assertions": [
                {
                    "label": "c2pa.training-mining",
                    "data": {
                        "entries": {
                            "c2pa.ai_generative_training": {"use": "notAllowed"}
                        }
                    }
                }
            ]
        }

        integration.embed_c2pa_metadata(
            media_file=self.media_file,
            manifest_data=manifest_data,
            ingredient_file=self.media_file,
            resource_file=self.media_file,
            output_file=self.signed_media
        )

        assert os.path.exists(self.signed_media), "Signed media file not created"
        
        LOG.info("C2PA metadata embedded successfully")

    def test_c2pa_metadata_reading(self):
        """Test C2PA metadata reading with X.509 validation."""
        integration = C2PAIntegrationTest(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )

        c2pa_data = integration.read_c2pa_metadata(self.signed_media)
        
        assert isinstance(c2pa_data, dict), "C2PA data not returned as dict"
        assert "claim_generator_info" in c2pa_data, "Claim generator info missing"
        assert "title" in c2pa_data, "Title missing from C2PA data"
        assert "x509_verification" in c2pa_data, "X.509 verification result missing"
        
        LOG.info(f"C2PA metadata read successfully: {c2pa_data['title']}")

    def test_certificate_chain_verification(self):
        """Test certificate chain verification method."""
        integration = C2PAIntegrationTest(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )

        result = integration.verify_certificate_chain(self.cert_path)
        assert result, "Certificate chain verification failed"
        
        LOG.info("Certificate chain verification method test passed")

    def test_in_toto_correlation(self):
        """Test correlation with in-toto metadata."""
        integration = C2PAIntegrationTest(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )

        # Read C2PA data
        c2pa_data = integration.read_c2pa_metadata(self.signed_media)

        # Create mock in-toto metadata
        in_toto_data = {
            "_type": "link",
            "name": c2pa_data.get("title", "ITE-7 Test Media"),
            "signature": {"keyid": "test-key"},
            "materials": {},
            "products": {}
        }

        with open(self.in_toto_metadata, 'w') as f:
            json.dump(in_toto_data, f)

        # Test correlation
        result = integration.correlate_with_in_toto(c2pa_data, self.in_toto_metadata)
        assert result, "C2PA and in-toto correlation failed"
        
        LOG.info("C2PA and in-toto correlation test passed")

    def test_certificate_info_access(self):
        """Test certificate information access."""
        integration = C2PAIntegrationTest(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )

        cert_info = integration.get_certificate_info()
        assert isinstance(cert_info, dict), "Certificate info not returned as dict"
        assert len(cert_info) > 0, "Certificate info is empty"
        
        LOG.info(f"Certificate info access test passed: {cert_info.get('subject', {})}")

    def test_error_handling(self):
        """Test error handling for invalid inputs."""
        # Test with non-existent certificate file
        try:
            load_x509_certificate("/non/existent/cert.pem")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass  # Expected

        # Test with empty certificate chain
        result = validate_x509_certificate_chain([])
        assert not result, "Empty certificate chain should fail validation"
        
        LOG.info("Error handling tests passed")

    def run_all_tests(self):
        """Run all tests and report results."""
        LOG.info("Starting ITE-7 C2PA integration test suite")
        
        # Run all tests
        tests = [
            ("Certificate Generation", self.test_certificate_generation),
            ("Certificate Loading", self.test_certificate_loading),
            ("Certificate Chain Validation", self.test_certificate_chain_validation),
            ("Media File Creation", self.test_media_file_creation),
            ("C2PA Integration Initialization", self.test_c2pa_integration_initialization),
            ("C2PA Metadata Embedding", self.test_c2pa_metadata_embedding),
            ("C2PA Metadata Reading", self.test_c2pa_metadata_reading),
            ("Certificate Chain Verification", self.test_certificate_chain_verification),
            ("In-Toto Correlation", self.test_in_toto_correlation),
            ("Certificate Info Access", self.test_certificate_info_access),
            ("Error Handling", self.test_error_handling),
        ]

        passed = 0
        failed = 0

        for test_name, test_func in tests:
            if self.run_test(test_name, test_func):
                passed += 1
            else:
                failed += 1

        # Print summary
        LOG.info("=" * 60)
        LOG.info("TEST SUITE SUMMARY")
        LOG.info("=" * 60)
        
        for test_name, result, error in self.test_results:
            status_symbol = "✅" if result == "PASS" else "❌"
            LOG.info(f"{status_symbol} {test_name}: {result}")
            if error:
                LOG.info(f"   Error: {error}")

        LOG.info("=" * 60)
        LOG.info(f"Total Tests: {len(tests)}")
        LOG.info(f"Passed: {passed}")
        LOG.info(f"Failed: {failed}")
        LOG.info(f"Success Rate: {(passed/len(tests)*100):.1f}%")
        
        if failed == 0:
            LOG.info("🎉 ALL TESTS PASSED! ITE-7 implementation is working correctly.")
        else:
            LOG.error(f"❌ {failed} tests failed. Please review the implementation.")

        return failed == 0


def main():
    """Main entry point for the test suite."""
    print("ITE-7 C2PA Integration Test Suite")
    print("=" * 50)
    print("Testing X.509 certificate-based C2PA integration")
    print("as specified in in-toto Enhancement 7 (ITE-7)")
    print()

    test_suite = ITE7TestSuite()
    
    try:
        success = test_suite.run_all_tests()
        return 0 if success else 1
    except Exception as e:
        LOG.error(f"Test suite execution failed: {e}")
        return 1
    finally:
        test_suite.cleanup()


if __name__ == "__main__":
    sys.exit(main())