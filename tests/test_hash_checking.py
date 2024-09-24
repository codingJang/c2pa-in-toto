from in_toto.runlib import record_artifacts_as_dict

# Example usage
artifacts = ['c2pa:images/signed_media.jpg', 'images/original_media.jpg', 'images/A.jpg', 'images/A_thumbnail.jpg']
artifact_hashes = record_artifacts_as_dict(artifacts)
print(artifact_hashes)