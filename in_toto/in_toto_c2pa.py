#!/usr/bin/env python
"""
in-toto-c2pa: Command line interface for C2PA integration with in-toto and ITE-7 X.509 support.

This tool provides functionality to:
- Embed C2PA metadata into media files with X.509 certificate-based signing
- Read and validate C2PA metadata from media files
- Correlate C2PA metadata with in-toto link metadata
- Verify X.509 certificate chains used for signing
"""

import argparse
import sys
import logging
import json
import os
from typing import Dict, Any

from in_toto import __version__ as in_toto_version
from in_toto.c2pa_integration import C2PAIntegration
from in_toto.c2pa_utils import load_x509_certificate, extract_certificate_info
from in_toto.common_args import (
    add_common_args,
    set_common_args,
    title_case_action_groups
)

# Setup logging
LOG = logging.getLogger(__name__)


def create_parser():
    """Create and configure the argument parser for in-toto-c2pa."""
    parser = argparse.ArgumentParser(
        description="in-toto C2PA integration tool with ITE-7 X.509 certificate support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Embed C2PA metadata with X.509 signing
  %(prog)s embed --media input.jpg --output signed.jpg \\
                 --private-key key.pem --cert-chain cert.pem \\
                 --manifest manifest.json

  # Read C2PA metadata with X.509 validation
  %(prog)s read --media signed.jpg --trusted-ca ca.pem

  # Verify certificate chain
  %(prog)s verify-cert --cert-chain cert.pem --trusted-ca ca.pem

  # Correlate with in-toto metadata
  %(prog)s correlate --media signed.jpg --in-toto metadata.link
        """
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"in-toto-c2pa {in_toto_version}"
    )

    # Add common arguments
    add_common_args(parser)

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
        metavar="COMMAND",
        required=True
    )

    # Embed command
    embed_parser = subparsers.add_parser(
        "embed",
        help="Embed C2PA metadata into media file with X.509 signing",
        description="Embed signed C2PA metadata into a media file using X.509 certificates."
    )
    embed_parser.add_argument(
        "--media",
        required=True,
        help="Path to the input media file"
    )
    embed_parser.add_argument(
        "--output",
        required=True,
        help="Path to the output media file with embedded C2PA metadata"
    )
    embed_parser.add_argument(
        "--private-key",
        required=True,
        help="Path to the private key file for signing"
    )
    embed_parser.add_argument(
        "--cert-chain",
        required=True,
        help="Path to the X.509 certificate chain file"
    )
    embed_parser.add_argument(
        "--manifest",
        help="Path to JSON file containing manifest data (optional)"
    )
    embed_parser.add_argument(
        "--ingredient",
        help="Path to ingredient file (defaults to input media)"
    )
    embed_parser.add_argument(
        "--resource",
        help="Path to resource file like thumbnail (optional)"
    )
    embed_parser.add_argument(
        "--trusted-ca",
        help="Path to trusted CA certificate for validation"
    )

    # Read command
    read_parser = subparsers.add_parser(
        "read",
        help="Read and validate C2PA metadata from media file",
        description="Read C2PA metadata from a media file and validate X.509 certificates."
    )
    read_parser.add_argument(
        "--media",
        required=True,
        help="Path to the media file with C2PA metadata"
    )
    read_parser.add_argument(
        "--trusted-ca",
        help="Path to trusted CA certificate for validation"
    )
    read_parser.add_argument(
        "--output",
        help="Path to save extracted metadata as JSON"
    )

    # Verify certificate command
    verify_parser = subparsers.add_parser(
        "verify-cert",
        help="Verify X.509 certificate chain",
        description="Verify an X.509 certificate chain against a trusted CA."
    )
    verify_parser.add_argument(
        "--cert-chain",
        required=True,
        help="Path to the certificate chain file"
    )
    verify_parser.add_argument(
        "--trusted-ca",
        help="Path to trusted CA certificate"
    )

    # Correlate command
    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Correlate C2PA metadata with in-toto metadata",
        description="Correlate C2PA metadata with in-toto link metadata using X.509 certificates."
    )
    correlate_parser.add_argument(
        "--media",
        required=True,
        help="Path to the media file with C2PA metadata"
    )
    correlate_parser.add_argument(
        "--in-toto",
        required=True,
        help="Path to the in-toto link metadata file"
    )
    correlate_parser.add_argument(
        "--trusted-ca",
        help="Path to trusted CA certificate for validation"
    )

    # Certificate info command
    cert_info_parser = subparsers.add_parser(
        "cert-info",
        help="Display X.509 certificate information",
        description="Extract and display information from an X.509 certificate."
    )
    cert_info_parser.add_argument(
        "--cert",
        required=True,
        help="Path to the certificate file"
    )

    title_case_action_groups(parser)
    return parser


def cmd_embed(args: argparse.Namespace) -> int:
    """Handle the embed command."""
    try:
        LOG.info(f"Embedding C2PA metadata into {args.output}")

        # Initialize C2PA integration
        integration = C2PAIntegration(
            private_key_path=args.private_key,
            certs_path=args.cert_chain,
            trusted_ca_path=args.trusted_ca
        )

        # Load manifest data
        if args.manifest:
            with open(args.manifest, 'r') as f:
                manifest_data = json.load(f)
        else:
            # Default manifest
            manifest_data = {
                "claim_generator_info": [{
                    "name": "in-toto-c2pa",
                    "version": in_toto_version
                }],
                "title": os.path.basename(args.media),
                "assertions": []
            }

        # Set default paths
        ingredient_file = args.ingredient or args.media
        resource_file = args.resource or args.media

        # Embed C2PA metadata
        integration.embed_c2pa_metadata(
            media_file=args.media,
            manifest_data=manifest_data,
            ingredient_file=ingredient_file,
            resource_file=resource_file,
            output_file=args.output
        )

        LOG.info("C2PA metadata embedded successfully")
        return 0

    except Exception as e:
        LOG.error(f"Failed to embed C2PA metadata: {e}")
        return 1


def cmd_read(args: argparse.Namespace) -> int:
    """Handle the read command."""
    try:
        LOG.info(f"Reading C2PA metadata from {args.media}")

        # Initialize C2PA integration (private key not needed for reading)
        integration = C2PAIntegration(
            private_key_path="",  # Not needed for reading
            certs_path="",  # Not needed for reading
            trusted_ca_path=args.trusted_ca
        )

        # Read C2PA metadata
        c2pa_data = integration.read_c2pa_metadata(args.media)

        # Output metadata
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(c2pa_data, f, indent=2, default=str)
            LOG.info(f"Metadata saved to {args.output}")
        else:
            print(json.dumps(c2pa_data, indent=2, default=str))

        return 0

    except Exception as e:
        LOG.error(f"Failed to read C2PA metadata: {e}")
        return 1


def cmd_verify_cert(args: argparse.Namespace) -> int:
    """Handle the verify-cert command."""
    try:
        LOG.info(f"Verifying certificate chain: {args.cert_chain}")

        # Initialize with dummy paths for verification
        integration = C2PAIntegration(
            private_key_path="",
            certs_path=args.cert_chain,
            trusted_ca_path=args.trusted_ca
        )

        # Verify certificate chain
        is_valid = integration.verify_certificate_chain(args.cert_chain)

        if is_valid:
            LOG.info("Certificate chain verification: PASSED")
            return 0
        else:
            LOG.error("Certificate chain verification: FAILED")
            return 1

    except Exception as e:
        LOG.error(f"Certificate verification error: {e}")
        return 1


def cmd_correlate(args: argparse.Namespace) -> int:
    """Handle the correlate command."""
    try:
        LOG.info(f"Correlating C2PA metadata with in-toto metadata")

        # Initialize C2PA integration
        integration = C2PAIntegration(
            private_key_path="",
            certs_path="",
            trusted_ca_path=args.trusted_ca
        )

        # Read C2PA metadata
        c2pa_data = integration.read_c2pa_metadata(args.media)

        # Correlate with in-toto metadata
        correlation_result = integration.correlate_with_in_toto(
            c2pa_data, args.in_toto
        )

        if correlation_result:
            LOG.info("Correlation: PASSED")
            return 0
        else:
            LOG.error("Correlation: FAILED")
            return 1

    except Exception as e:
        LOG.error(f"Correlation error: {e}")
        return 1


def cmd_cert_info(args: argparse.Namespace) -> int:
    """Handle the cert-info command."""
    try:
        LOG.info(f"Extracting certificate information from {args.cert}")

        # Load certificate
        cert = load_x509_certificate(args.cert)
        cert_info = extract_certificate_info(cert)

        # Display certificate information
        print(json.dumps(cert_info, indent=2, default=str))

        return 0

    except Exception as e:
        LOG.error(f"Failed to extract certificate information: {e}")
        return 1


def main(argv=None):
    """Main entry point for in-toto-c2pa."""
    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser()
    args = parser.parse_args(argv)

    # Set up common arguments
    set_common_args(args)

    # Dispatch to command handlers
    command_handlers = {
        "embed": cmd_embed,
        "read": cmd_read,
        "verify-cert": cmd_verify_cert,
        "correlate": cmd_correlate,
        "cert-info": cmd_cert_info,
    }

    handler = command_handlers.get(args.command)
    if not handler:
        LOG.error(f"Unknown command: {args.command}")
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())