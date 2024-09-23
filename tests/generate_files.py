import os
import json
import hashlib
from pathlib import Path
from PIL import Image

def create_directories(paths):
    """
    Create directories for the given paths if they do not exist.

    Args:
        paths (list of Path): List of Path objects representing file paths.
    """
    for path in paths:
        directory = path.parent
        if not directory.exists():
            print(f"Creating directory: {directory}")
            directory.mkdir(parents=True, exist_ok=True)
        else:
            print(f"Directory already exists: {directory}")

def create_dummy_image(path, size=(800, 600), color=(255, 0, 0)):
    """
    Create a dummy JPEG image with the specified size and color.

    Args:
        path (Path): Path where the image will be saved.
        size (tuple): Size of the image in pixels (width, height).
        color (tuple): RGB color tuple.
    """
    print(f"Creating dummy image: {path}")
    image = Image.new('RGB', size, color)
    image.save(path, format='JPEG')
    print(f"Image saved: {path}")

def compute_sha256(file_path):
    """
    Compute the SHA256 hash of a file.

    Args:
        file_path (Path): Path to the file.

    Returns:
        str: Hexadecimal SHA256 hash of the file.
    """
    sha256_hash = hashlib.sha256()
    print(f"Computing SHA256 for: {file_path}")
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    hash_digest = sha256_hash.hexdigest()
    print(f"SHA256: {hash_digest}")
    return hash_digest

def create_link_metadata(link_path, step_name, command, products, signatures):
    """
    Create an in-toto link metadata JSON file.

    Args:
        link_path (Path): Path where the link metadata will be saved.
        step_name (str): Name of the in-toto step.
        command (list): List of command strings executed in the step.
        products (dict): Dictionary of products with their SHA256 hashes.
        signatures (list): List of signature dictionaries.
    """
    link_metadata = {
        "signed": {
            "_type": "link",
            "name": step_name,
            "command": command,
            "materials": {},
            "products": products,
            "byproducts": {
                "stderr": "",
                "stdout": "",
                "return-value": 0
            },
            "environment": {
                "variables": [""],
                "filesystem": "",
                "workdir": ""
            }
        },
        "signatures": signatures
    }
    print(f"Creating link metadata: {link_path}")
    with open(link_path, 'w') as f:
        json.dump(link_metadata, f, indent=4)
    print(f"Link metadata saved: {link_path}")

def main():
    # Define paths to necessary files
    original_media = Path("images/original_media.jpg")
    ingredient_file = Path("images/A.jpg")
    resource_file = Path("images/A_thumbnail.jpg")
    link_metadata = Path("images/link_metadata.link")

    # List of all file paths to be created (excluding output_media)
    file_paths = [original_media, ingredient_file, resource_file, link_metadata]

    # Step 1: Create necessary directories
    create_directories(file_paths)

    # Step 2: Create dummy images
    create_dummy_image(original_media, size=(800, 600), color=(255, 0, 0))      # Red image
    create_dummy_image(ingredient_file, size=(800, 600), color=(0, 255, 0))     # Green image
    create_dummy_image(resource_file, size=(200, 150), color=(0, 0, 255))       # Blue thumbnail

    # Step 3: Compute SHA256 hashes for A.jpg
    a_jpg_hash = compute_sha256(ingredient_file)

    # Step 4: Create products dictionary with the hash
    products = {
        "A.jpg": { "sha256": a_jpg_hash }
    }

    # Step 5: Define signatures (using dummy values for illustration)
    signatures = [
        {
            "keyid": "ALICES_KEYID",
            "sig": "dummy_signature_here"
        }
    ]

    # Step 6: Create link_metadata.link
    create_link_metadata(
        link_path=link_metadata,
        step_name="write-code",
        command=["vi", "A.jpg"],
        products=products,
        signatures=signatures
    )

    print("\nAll files generated successfully.")

if __name__ == "__main__":
    main()
