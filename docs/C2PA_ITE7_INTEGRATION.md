# C2PA Integration with in-toto ITE-7 X.509 Certificate Support

This document describes the C2PA (Coalition for Content Provenance and Authenticity) integration with in-toto, enhanced with ITE-7 (in-toto Enhancement 7) X.509 certificate-based signing and verification capabilities.

## Overview

The C2PA integration allows in-toto to work with C2PA-enabled media files, providing content provenance and authenticity verification. With ITE-7 support, this integration now includes comprehensive X.509 certificate-based signing and verification, enabling:

- **Certificate-based signing**: Use X.509 certificates for signing C2PA manifests
- **Certificate chain validation**: Verify certificate chains against trusted CAs
- **Enhanced correlation**: Correlate C2PA and in-toto metadata using certificate information
- **Trust anchor support**: Configure trusted CA certificates for verification

## Components

### Core Classes

#### `C2PAIntegration`

The main class for C2PA operations with ITE-7 X.509 support.

```python
from in_toto.c2pa_integration import C2PAIntegration

# Initialize with X.509 certificates
integration = C2PAIntegration(
    private_key_path="signing_key.pem",
    certs_path="cert_chain.pem", 
    trusted_ca_path="ca_cert.pem"  # Optional trusted CA
)
```

**Key Methods:**
- `embed_c2pa_metadata()`: Embed C2PA metadata with X.509 certificate information
- `read_c2pa_metadata()`: Read and validate C2PA metadata with X.509 verification
- `correlate_with_in_toto()`: Correlate C2PA and in-toto metadata using certificates
- `verify_certificate_chain()`: Verify X.509 certificate chains
- `get_certificate_info()`: Get information about the loaded signing certificate

### Utility Functions

#### `c2pa_utils.py`

Provides X.509 certificate utilities for ITE-7 support:

- `load_x509_certificate()`: Load X.509 certificates from PEM/DER files
- `validate_x509_certificate_chain()`: Validate certificate chains with expiry and signature checks
- `extract_certificate_info()`: Extract certificate metadata (subject, issuer, serial, etc.)
- `create_c2pa_signer_with_x509()`: Create C2PA signers with X.509 certificates
- `verify_c2pa_signature_with_x509()`: Verify C2PA signatures using certificates

### C2PA Resolver

#### `_c2pa_resolver.py`

Integrates with in-toto's resolver system to extract hash data from C2PA manifests.

```python
from in_toto.resolver._c2pa_resolver import C2PAResolver

resolver = C2PAResolver()
hashes = resolver.hash_artifacts(["c2pa:signed_media.jpg"])
```

## ITE-7 X.509 Certificate Features

### Certificate Chain Validation

The implementation validates certificate chains according to ITE-7 requirements:

1. **Expiry Validation**: Checks that certificates are within their validity period
2. **Signature Validation**: Verifies signatures in the certificate chain
3. **Trust Anchor Validation**: Validates against trusted CA certificates
4. **Certificate Information Extraction**: Extracts and correlates certificate metadata

### Enhanced C2PA Metadata

C2PA manifests are enhanced with X.509 certificate information:

```json
{
  "claim_generator_info": [...],
  "title": "Signed Media",
  "certificate_info": {
    "subject": {
      "commonName": "signer.example.com",
      "organizationName": "Example Organization"
    },
    "issuer": {
      "commonName": "Example CA",
      "organizationName": "Example CA Organization"
    },
    "serial_number": "123456789",
    "signature_algorithm": "sha256"
  },
  "assertions": [...]
}
```

### Correlation with in-toto Metadata

The integration correlates C2PA certificate information with in-toto link metadata:

1. **Certificate Consistency**: Validates that the same certificate was used for both C2PA and in-toto signing
2. **Signer Identity**: Correlates signer identity across both metadata formats
3. **Trust Validation**: Ensures both metadata sources are signed by trusted entities

## Usage Examples

### Command Line Interface

Use the `in-toto-c2pa` command-line tool:

```bash
# Embed C2PA metadata with X.509 signing
in-toto-c2pa embed \
  --media input.jpg \
  --output signed.jpg \
  --private-key key.pem \
  --cert-chain cert.pem \
  --trusted-ca ca.pem

# Read C2PA metadata with X.509 validation
in-toto-c2pa read \
  --media signed.jpg \
  --trusted-ca ca.pem \
  --output metadata.json

# Verify certificate chain
in-toto-c2pa verify-cert \
  --cert-chain cert.pem \
  --trusted-ca ca.pem

# Correlate with in-toto metadata
in-toto-c2pa correlate \
  --media signed.jpg \
  --in-toto metadata.link \
  --trusted-ca ca.pem

# Display certificate information
in-toto-c2pa cert-info --cert cert.pem
```

### Programmatic Usage

```python
from in_toto.c2pa_integration import C2PAIntegration

# Initialize with certificates
integration = C2PAIntegration(
    private_key_path="signing_key.pem",
    certs_path="cert_chain.pem",
    trusted_ca_path="ca_cert.pem"
)

# Embed C2PA metadata
manifest_data = {
    "claim_generator_info": [{"name": "my_app", "version": "1.0"}],
    "title": "Signed Content",
    "assertions": []
}

integration.embed_c2pa_metadata(
    media_file="input.jpg",
    manifest_data=manifest_data,
    ingredient_file="input.jpg",
    resource_file="thumbnail.jpg",
    output_file="signed.jpg"
)

# Read and validate
c2pa_data = integration.read_c2pa_metadata("signed.jpg")

# Correlate with in-toto
correlation_result = integration.correlate_with_in_toto(
    c2pa_data, "metadata.link"
)
```

### Example Workflow

See `examples/c2pa_ite7_example.py` for a complete workflow demonstration that includes:

1. Creating test X.509 certificates
2. Embedding C2PA metadata with certificate information
3. Reading and validating with X.509 verification
4. Correlating with in-toto metadata
5. Certificate chain verification

## Certificate Requirements

### Certificate Format

- **Supported Formats**: PEM and DER encoding
- **Key Types**: RSA keys (2048+ bits recommended)
- **Certificate Extensions**: Standard X.509v3 extensions

### Certificate Chain Structure

```
Root CA Certificate
  └── Intermediate CA Certificate (optional)
      └── Signing Certificate
```

### Recommended Certificate Attributes

**Root/Intermediate CA:**
- `basicConstraints: CA:TRUE`
- `keyUsage: keyCertSign, cRLSign`

**Signing Certificate:**
- `keyUsage: digitalSignature, nonRepudiation`
- `extendedKeyUsage: codeSigning`

## Security Considerations

### Certificate Validation

1. **Chain Validation**: All certificates in the chain are validated for proper signatures
2. **Expiry Checks**: Certificates must be within their validity period
3. **Trust Anchors**: Only certificates signed by trusted CAs are accepted
4. **Revocation**: Consider implementing CRL/OCSP checking for production use

### Best Practices

1. **Private Key Security**: Store private keys securely (HSM, secure key stores)
2. **Certificate Lifecycle**: Implement proper certificate renewal and rotation
3. **Trust Store Management**: Maintain and update trusted CA certificates
4. **Audit Logging**: Log all certificate operations for security auditing

## Dependencies

The C2PA integration requires:

```
c2pa-python>=0.4.0
cryptography>=3.4.8
```

Install with:
```bash
pip install c2pa-python cryptography
```

## Testing

Run the comprehensive test suite:

```bash
python -m pytest tests/test_c2pa_in_toto.py -v
```

The tests include:
- Certificate loading and validation
- C2PA metadata operations
- X.509 chain verification
- Integration with in-toto metadata
- Error handling scenarios

## Troubleshooting

### Common Issues

**Certificate Loading Errors:**
- Verify certificate format (PEM/DER)
- Check file permissions and paths
- Ensure certificates are not corrupted

**Chain Validation Failures:**
- Verify certificate chain order (leaf to root)
- Check certificate expiry dates
- Ensure proper CA signatures

**C2PA Integration Errors:**
- Install required C2PA dependencies
- Check media file format compatibility
- Verify private key matches certificate

### Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Compliance

This implementation aligns with:

- **ITE-7**: in-toto Enhancement 7 for X.509 certificate signing and verification
- **C2PA Specification**: Coalition for Content Provenance and Authenticity standards
- **X.509 Standards**: ITU-T X.509 certificate format and validation
- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate and CRL Profile

## Contributing

When contributing to the C2PA integration:

1. Follow ITE-7 specification requirements
2. Maintain compatibility with C2PA standards
3. Include comprehensive tests for new features
4. Update documentation for API changes
5. Consider security implications of modifications

## References

- [ITE-7: Signing & Verification With X509](https://github.com/in-toto/ITE/tree/master/ITE/7)
- [C2PA Specification](https://c2pa.org/specifications/)
- [RFC 5280: Internet X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [in-toto Specification](https://github.com/in-toto/docs/blob/master/in-toto-spec.md)