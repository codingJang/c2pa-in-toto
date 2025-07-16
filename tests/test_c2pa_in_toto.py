#!/usr/bin/env python3
"""
Unit tests for C2PA integration with in-toto and ITE-7 X.509 certificate support.
"""

import unittest
import tempfile
import os
import shutil
import json
from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from in_toto.c2pa_integration import C2PAIntegration
from in_toto.c2pa_utils import (
    load_x509_certificate,
    validate_x509_certificate_chain,
    extract_certificate_info,
    create_c2pa_signer_with_x509,
    verify_c2pa_signature_with_x509
)
from in_toto.models.metadata import Metadata


class TestC2PAIntegration(unittest.TestCase):
    """Test cases for C2PA integration with ITE-7 X.509 support."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.private_key_path = os.path.join(self.test_dir, "test_key.pem")
        self.cert_path = os.path.join(self.test_dir, "test_cert.pem")
        self.ca_cert_path = os.path.join(self.test_dir, "ca_cert.pem")
        self.media_file = os.path.join(self.test_dir, "test_media.jpg")
        self.output_file = os.path.join(self.test_dir, "output_media.jpg")
        
        # Create mock certificates for testing
        self._create_test_certificates()
        self._create_test_media_file()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir)

    def _create_test_certificates(self):
        """Create test X.509 certificates for testing."""
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Save private key
        with open(self.private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        # Save certificate
        with open(self.cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Save CA certificate (same as cert for testing)
        with open(self.ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def _create_test_media_file(self):
        """Create a test media file."""
        # Create a minimal JPEG-like file for testing
        jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
        jpeg_end = b'\xff\xd9'
        
        with open(self.media_file, 'wb') as f:
            f.write(jpeg_header + b'\x00' * 1000 + jpeg_end)

    def test_c2pa_integration_initialization(self):
        """Test C2PAIntegration initialization with X.509 certificates."""
        integration = C2PAIntegration(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )
        
        self.assertIsNotNone(integration.signer)
        self.assertIsNotNone(integration.trusted_ca_cert)
        self.assertIsNotNone(integration.signing_cert)
        self.assertIsInstance(integration.signing_cert_info, dict)

    def test_get_certificate_info(self):
        """Test certificate information extraction."""
        integration = C2PAIntegration(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path
        )
        
        cert_info = integration.get_certificate_info()
        self.assertIsInstance(cert_info, dict)
        self.assertIn('subject', cert_info)
        self.assertIn('issuer', cert_info)
        self.assertIn('serial_number', cert_info)

    @patch('in_toto.c2pa_integration.load_c2pa_manifest')
    @patch('in_toto.c2pa_integration.validate_c2pa_manifest')
    def test_read_c2pa_metadata(self, mock_validate, mock_load):
        """Test reading C2PA metadata with X.509 validation."""
        mock_c2pa_data = {
            "claim_generator_info": [{"name": "test", "version": "1.0"}],
            "title": "Test Media",
            "thumbnail": {},
            "assertions": []
        }
        mock_load.return_value = mock_c2pa_data
        mock_validate.return_value = True

        integration = C2PAIntegration(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )
        
        result = integration.read_c2pa_metadata(self.media_file)
        
        self.assertIsInstance(result, dict)
        self.assertIn('x509_verification', result)
        mock_load.assert_called_once_with(self.media_file)
        mock_validate.assert_called_once()

    @patch('in_toto.c2pa_integration.Builder')
    def test_embed_c2pa_metadata(self, mock_builder):
        """Test embedding C2PA metadata with certificate information."""
        mock_builder_instance = MagicMock()
        mock_builder.return_value = mock_builder_instance

        integration = C2PAIntegration(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path
        )
        
        manifest_data = {
            "claim_generator_info": [{"name": "test", "version": "1.0"}],
            "title": "Test Media"
        }
        
        integration.embed_c2pa_metadata(
            media_file=self.media_file,
            manifest_data=manifest_data,
            ingredient_file=self.media_file,
            resource_file=self.media_file,
            output_file=self.output_file
        )
        
        # Verify certificate info was added to manifest
        mock_builder.assert_called_once()
        call_args = mock_builder.call_args[0][0]
        self.assertIn('certificate_info', call_args)
        
        # Verify builder methods were called
        mock_builder_instance.add_resource_file.assert_called_once()
        mock_builder_instance.add_ingredient_file.assert_called_once()
        mock_builder_instance.sign_file.assert_called_once()

    def test_verify_certificate_chain(self):
        """Test X.509 certificate chain verification."""
        integration = C2PAIntegration(
            private_key_path=self.private_key_path,
            certs_path=self.cert_path,
            trusted_ca_path=self.ca_cert_path
        )
        
        result = integration.verify_certificate_chain(self.cert_path)
        self.assertTrue(result)


class TestC2PAUtils(unittest.TestCase):
    """Test cases for C2PA utility functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.cert_path = os.path.join(self.test_dir, "test_cert.pem")
        self._create_test_certificate()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir)

    def _create_test_certificate(self):
        """Create a test X.509 certificate."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        with open(self.cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def test_load_x509_certificate(self):
        """Test loading X.509 certificates."""
        cert = load_x509_certificate(self.cert_path)
        self.assertIsInstance(cert, x509.Certificate)

    def test_extract_certificate_info(self):
        """Test extracting certificate information."""
        cert = load_x509_certificate(self.cert_path)
        cert_info = extract_certificate_info(cert)
        
        self.assertIsInstance(cert_info, dict)
        self.assertIn('subject', cert_info)
        self.assertIn('issuer', cert_info)
        self.assertIn('serial_number', cert_info)
        self.assertIn('not_valid_before', cert_info)
        self.assertIn('not_valid_after', cert_info)

    def test_validate_x509_certificate_chain(self):
        """Test X.509 certificate chain validation."""
        cert = load_x509_certificate(self.cert_path)
        cert_chain = [cert]
        
        # Test with self-signed certificate (should pass basic checks)
        result = validate_x509_certificate_chain(cert_chain)
        self.assertTrue(result)

    def test_verify_c2pa_signature_with_x509(self):
        """Test C2PA signature verification with X.509 certificates."""
        cert = load_x509_certificate(self.cert_path)
        manifest_data = {
            "signature": {
                "alg": "PS256"
            }
        }
        
        # This is a placeholder test as full verification requires C2PA integration
        result = verify_c2pa_signature_with_x509(manifest_data, [cert])
        self.assertTrue(result)  # Placeholder implementation returns True


class TestC2PAResolver(unittest.TestCase):
    """Test cases for C2PA resolver integration."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir)

    def test_resolver_initialization(self):
        """Test C2PA resolver initialization."""
        from in_toto.resolver._c2pa_resolver import C2PAResolver
        
        resolver = C2PAResolver(output_dir=self.test_dir)
        self.assertEqual(resolver.SCHEME, "c2pa")
        self.assertEqual(resolver.output_dir, self.test_dir)

    def test_strip_scheme_prefix(self):
        """Test stripping C2PA scheme prefix."""
        from in_toto.resolver._c2pa_resolver import C2PAResolver
        
        resolver = C2PAResolver()
        path, prefix = resolver._strip_scheme_prefix("c2pa:test/file.jpg")
        self.assertEqual(path, "test/file.jpg")
        self.assertEqual(prefix, "c2pa:")


if __name__ == '__main__':
    unittest.main()
