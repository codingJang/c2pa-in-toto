import os
import subprocess

# Set the output directory
output_dir = 'tests/fixtures'
os.makedirs(output_dir, exist_ok=True)

# Paths for the files
ca_key_path = os.path.join(output_dir, 'SelfCert.key')
ca_crt_der_path = os.path.join(output_dir, 'SelfCert-ca.crt')
ca_crt_pem_path = os.path.join(output_dir, 'SelfCert-ca.pem')
user_key_path = os.path.join(output_dir, 'SelfCert-sign.key')
user_csr_path = os.path.join(output_dir, 'SelfCert-sign.csr')
user_cert_path = os.path.join(output_dir, 'SelfCert-sign.pem')
user_exts_path = os.path.join(output_dir, 'user_cert_ext.cnf')

# Generate CA private key (SelfCert.key)
subprocess.run([
    'openssl', 'genrsa', '-out', ca_key_path, '4096'
], check=True)

# Generate self-signed CA certificate in DER format (SelfCert-ca.crt)
subprocess.run([
    'openssl', 'req', '-x509', '-new', '-nodes',
    '-key', ca_key_path,
    '-sha256', '-days', '3650',
    '-outform', 'der',
    '-out', ca_crt_der_path,
    '-subj', '/C=US/ST=California/L=San Francisco/O=My CA/CN=myca.example.com'
], check=True)

# Convert CA certificate to PEM format (SelfCert-ca.pem)
subprocess.run([
    'openssl', 'x509', '-in', ca_crt_der_path,
    '-inform', 'der',
    '-outform', 'pem',
    '-out', ca_crt_pem_path
], check=True)

# Generate user private key (SelfCert-sign.key)
subprocess.run([
    'openssl', 'genrsa', '-out', user_key_path, '4096'
], check=True)

# Create a certificate signing request (CSR) for the user certificate
subprocess.run([
    'openssl', 'req', '-new', '-key', user_key_path,
    '-out', user_csr_path,
    '-subj', '/C=US/ST=California/L=San Francisco/O=My Organization/CN=user@example.com'
], check=True)

# Create a configuration file for the extensions (user_cert_ext.cnf)
with open(user_exts_path, 'w') as f:
    f.write('''[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = emailProtection
''')

# Sign the user certificate with the CA key and certificate using RSA-PSS padding
subprocess.run([
    'openssl', 'x509', '-req',
    '-in', user_csr_path,
    '-CA', ca_crt_pem_path,
    '-CAkey', ca_key_path,
    '-CAcreateserial',
    '-out', user_cert_path,
    '-days', '3600',
    '-sha256',
    '-extfile', user_exts_path,
    '-extensions', 'v3_req',
    '-sigopt', 'rsa_padding_mode:pss'
], check=True)
