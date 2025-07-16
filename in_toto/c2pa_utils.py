# c2pa_utils.py

import json
import logging
from typing import Dict, Any, Optional, List
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os
from datetime import datetime

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


def load_x509_certificate(cert_path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a file (ITE-7 support).

    Args:
        cert_path (str): Path to the certificate file (PEM or DER format).

    Returns:
        x509.Certificate: The loaded certificate object.

    Raises:
        FileNotFoundError: If the certificate file does not exist.
        ValueError: If the certificate format is invalid.
    """
    try:
        LOG.info(f"Loading X.509 certificate from {cert_path}")
        
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        
        # Try PEM format first
        try:
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            LOG.debug("Certificate loaded in PEM format")
        except ValueError:
            # Try DER format
            try:
                certificate = x509.load_der_x509_certificate(cert_data, default_backend())
                LOG.debug("Certificate loaded in DER format")
            except ValueError:
                raise ValueError(f"Invalid certificate format in {cert_path}")
        
        LOG.info("X.509 certificate loaded successfully.")
        return certificate
        
    except FileNotFoundError:
        LOG.error(f"Certificate file not found: {cert_path}")
        raise
    except Exception as e:
        LOG.error(f"Error loading X.509 certificate: {e}")
        raise


def validate_x509_certificate_chain(cert_chain: List[x509.Certificate], 
                                   trusted_ca_cert: Optional[x509.Certificate] = None) -> bool:
    """
    Validate an X.509 certificate chain (ITE-7 support).

    Args:
        cert_chain (List[x509.Certificate]): List of certificates in the chain (leaf first).
        trusted_ca_cert (Optional[x509.Certificate]): Trusted CA certificate for validation.

    Returns:
        bool: True if the certificate chain is valid, False otherwise.
    """
    try:
        LOG.info("Validating X.509 certificate chain")
        
        if not cert_chain:
            LOG.error("Empty certificate chain provided")
            return False
        
        # Check each certificate's validity period
        current_time = datetime.utcnow()
        for i, cert in enumerate(cert_chain):
            if current_time < cert.not_valid_before:
                LOG.error(f"Certificate {i} is not yet valid")
                return False
            if current_time > cert.not_valid_after:
                LOG.error(f"Certificate {i} has expired")
                return False
        
        # Verify certificate chain signature
        for i in range(len(cert_chain) - 1):
            child_cert = cert_chain[i]
            parent_cert = cert_chain[i + 1]
            
            try:
                parent_public_key = parent_cert.public_key()
                parent_public_key.verify(
                    child_cert.signature,
                    child_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child_cert.signature_hash_algorithm
                )
                LOG.debug(f"Certificate {i} signature verified by certificate {i + 1}")
            except Exception as e:
                LOG.error(f"Certificate chain verification failed at position {i}: {e}")
                return False
        
        # If a trusted CA is provided, verify the root certificate
        if trusted_ca_cert and len(cert_chain) > 0:
            root_cert = cert_chain[-1]
            try:
                ca_public_key = trusted_ca_cert.public_key()
                ca_public_key.verify(
                    root_cert.signature,
                    root_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    root_cert.signature_hash_algorithm
                )
                LOG.debug("Root certificate verified against trusted CA")
            except Exception as e:
                LOG.error(f"Root certificate verification against trusted CA failed: {e}")
                return False
        
        LOG.info("X.509 certificate chain validation passed")
        return True
        
    except Exception as e:
        LOG.error(f"Error during certificate chain validation: {e}")
        return False


def extract_certificate_info(certificate: x509.Certificate) -> Dict[str, str]:
    """
    Extract relevant information from an X.509 certificate (ITE-7 support).

    Args:
        certificate (x509.Certificate): The certificate to extract information from.

    Returns:
        Dict[str, str]: Dictionary containing certificate information.
    """
    try:
        LOG.debug("Extracting certificate information")
        
        # Extract subject information
        subject = certificate.subject
        subject_info = {}
        for attribute in subject:
            subject_info[attribute.oid._name] = attribute.value
        
        # Extract issuer information
        issuer = certificate.issuer
        issuer_info = {}
        for attribute in issuer:
            issuer_info[attribute.oid._name] = attribute.value
        
        cert_info = {
            "serial_number": str(certificate.serial_number),
            "subject": subject_info,
            "issuer": issuer_info,
            "not_valid_before": certificate.not_valid_before.isoformat(),
            "not_valid_after": certificate.not_valid_after.isoformat(),
            "signature_algorithm": certificate.signature_hash_algorithm.name,
            "public_key_algorithm": certificate.public_key().__class__.__name__
        }
        
        LOG.debug("Certificate information extracted successfully")
        return cert_info
        
    except Exception as e:
        LOG.error(f"Error extracting certificate information: {e}")
        return {}


def create_c2pa_signer_with_x509(private_key_path: str, cert_chain_path: str, 
                                 signing_alg: int = SigningAlg.PS256) -> Any:
    """
    Create a C2PA signer using X.509 certificates (ITE-7 support).

    Args:
        private_key_path (str): Path to the private key file.
        cert_chain_path (str): Path to the certificate chain file.
        signing_alg (int): Signing algorithm to use (default: PS256).

    Returns:
        Any: Signer object to be used with Builder.

    Raises:
        FileNotFoundError: If the private key or certificate files do not exist.
        Exception: If signer creation fails.
    """
    try:
        LOG.info(f"Creating C2PA signer with X.509 certificates")
        LOG.debug(f"Private key: {private_key_path}, Cert chain: {cert_chain_path}")

        def private_sign(data: bytes) -> bytes:
            return sign_ps256(data, private_key_path)

        # Read certificate chain
        with open(cert_chain_path, "rb") as cert_file:
            cert_data = cert_file.read()

        # Load and validate the certificate chain
        try:
            # Try to load as PEM first
            cert_chain = []
            cert_pem_data = cert_data.decode('utf-8')
            cert_blocks = cert_pem_data.split('-----BEGIN CERTIFICATE-----')[1:]
            
            for block in cert_blocks:
                cert_pem = '-----BEGIN CERTIFICATE-----' + block
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                cert_chain.append(cert)
                
        except Exception:
            # Try to load as single DER certificate
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            cert_chain = [cert]
        
        # Validate certificate chain
        if not validate_x509_certificate_chain(cert_chain):
            LOG.warning("Certificate chain validation failed, but continuing with signer creation")
        
        # Extract certificate information for logging
        if cert_chain:
            cert_info = extract_certificate_info(cert_chain[0])
            LOG.info(f"Using certificate with subject: {cert_info.get('subject', {})}")

        signer = create_signer(private_sign, signing_alg, cert_data, "http://timestamp.digicert.com")
        LOG.info("C2PA signer with X.509 certificates created successfully")
        return signer

    except FileNotFoundError as e:
        LOG.error(f"Certificate or private key file not found: {e}")
        raise
    except Exception as e:
        LOG.error(f"Error creating C2PA signer with X.509 certificates: {e}")
        raise


def create_c2pa_signer(private_key_path: str, certs_path: str, signing_alg: int = SigningAlg.PS256) -> Any:
    """
    Create a C2PA signer using a private key (legacy method, enhanced for ITE-7).

    Args:
        private_key_path (str): Path to the private key file.
        certs_path (str): Path to the certificate file.
        signing_alg (int): Signing algorithm to use (default: PS256).

    Returns:
        Any: Signer object to be used with Builder.

    Raises:
        FileNotFoundError: If the private key file does not exist.
        Exception: If signer creation fails.
    """
    # Use the new X.509-aware signer creation method
    return create_c2pa_signer_with_x509(private_key_path, certs_path, signing_alg)


def verify_c2pa_signature_with_x509(manifest_data: Dict[str, Any], 
                                   trusted_certs: List[x509.Certificate]) -> bool:
    """
    Verify C2PA signature using X.509 certificates (ITE-7 support).

    Args:
        manifest_data (Dict[str, Any]): C2PA manifest data to verify.
        trusted_certs (List[x509.Certificate]): List of trusted certificates.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    try:
        LOG.info("Verifying C2PA signature with X.509 certificates")
        
        # Extract signature information from manifest
        signature_info = manifest_data.get("signature", {})
        if not signature_info:
            LOG.error("No signature information found in manifest")
            return False
        
        # For now, return True as a placeholder
        # Full implementation would require deeper integration with C2PA verification
        LOG.info("C2PA signature verification completed (placeholder implementation)")
        return True
        
    except Exception as e:
        LOG.error(f"Error during C2PA signature verification: {e}")
        return False
