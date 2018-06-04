
"""
<Program Name>
  test_in_toto_sign.py
<Author>
  Sachit Malik <i.sachitmalik@gmail.com>
  Lukas Puehringer <luk.puehringer@gmail.com>
<Started>
  Wed Jun 21, 2017
<Copyright>
  See LICENSE for licensing information.
<Purpose>
  Test in_toto_sign command line tool.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest

from mock import patch
from in_toto import exceptions
import in_toto.gpg.util

from in_toto.in_toto_sign import main as in_toto_sign_main

import tests.common

WORKING_DIR = os.getcwd()



class TestInTotoSignTool(tests.common.CliTestCase):
  """Test in_toto_sign's main() - requires sys.argv patching; error logs/exits
  on Exception. """
  cli_main_func = staticmethod(in_toto_sign_main)

  @classmethod
  def setUpClass(self):
    # Backup original cwd
    self.working_dir = os.getcwd()

    # Find demo files
    demo_files = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "demo_files")

    # Find gpg keyring
    gpg_keyring_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa")

    # Create and change into temporary directory
    self.test_dir = os.path.realpath(tempfile.mkdtemp())
    os.chdir(self.test_dir)

    # Copy demo files to temp dir
    for file_path in os.listdir(demo_files):
      shutil.copy(os.path.join(demo_files, file_path), self.test_dir)

    # Copy gpg keyring to temp dir
    self.gnupg_home = os.path.join(self.test_dir, "rsa")
    shutil.copytree(gpg_keyring_path, self.gnupg_home)

    self.default_gpg_keyid = "8465a1e2e0fb2b40adb2478e18fb3f537e0c8a17"
    self.gpg_keyid1 = "7b3abb26b97b655ab9296bd15b0bd02e1c768c43"
    self.gpg_keyid2 = "8288ef560ed3795f9df2c0db56193089b285da58"

    self.layout_path = "demo.layout.template"
    self.link_path = "package.2f89b927.link"
    self.alice_path = "alice"
    self.alice_pub_path = "alice.pub"
    self.bob_path= "bob"
    self.bob_pub_path = "bob.pub"
    self.carl_path= "carl"
    self.carl_pub_path = "carl.pub"
    self.danny_path = "danny"
    self.danny_pub_path = "danny.pub"

  @classmethod
  def tearDownClass(self):
    """Change back to initial working dir and remove temp dir. """
    os.chdir(self.working_dir)
    shutil.rmtree(self.test_dir)


  def test_sign_and_verify(self):
    """Test signing and verifying Layout and Link metadata with
    different combinations of arguments. """

    # Sign Layout with multiple keys and write to "tmp.layout"
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", self.alice_path, self.bob_path,
        "-o", "tmp.layout",
        ], 0)

    # Verify "tmp.layout" (requires all keys)
    self.assert_cli_sys_exit([
        "-f", "tmp.layout",
        "-k", self.alice_pub_path, self.bob_pub_path,
        "--verify",
        ], 0)

    # Sign Layout "tmp.layout", appending new signature, write to "tmp.layout"
    self.assert_cli_sys_exit([
        "-f", "tmp.layout",
        "-k", self.carl_path,
        "-a"
        ], 0)

    # Verify "tmp.layout" (has three signatures now)
    self.assert_cli_sys_exit([
        "-f", "tmp.layout",
        "-k", self.alice_pub_path, self.bob_pub_path, self.carl_pub_path,
        "--verify"
        ], 0)

    # Sign Layout "tmp.layout" with ed25519 key, appending new signature,
    # write to "tmp.layout"
    self.assert_cli_sys_exit([
        "-f", "tmp.layout",
        "-k", self.danny_path,
        "-t", "ed25519",
        "-a"
        ], 0)

    # Verify "tmp.layout" (has four signatures now)
    self.assert_cli_sys_exit([
        "-f", "tmp.layout",
        "-k", self.alice_pub_path, self.bob_pub_path, self.carl_pub_path,
        self.danny_pub_path,
        "-t", "rsa", "rsa", "rsa", "ed25519",
        "--verify"
        ], 0)

    # Sign Link, replacing old signature
    # and write to same file as input
    self.assert_cli_sys_exit([
        "-f", self.link_path,
        "-k", self.bob_path,
        "-o", self.link_path,
        ], 0)

    # Verify Link
    self.assert_cli_sys_exit([
        "-f", self.link_path,
        "-k", self.bob_pub_path,
        "--verify"
        ], 0)

    # Replace signature to Link and store to new file using passed
    # key's (alice) id as infix
    self.assert_cli_sys_exit([
        "-f", self.link_path,
        "-k", self.alice_path
        ], 0)
    # Verify Link with alice's keyid as infix
    self.assert_cli_sys_exit([
        "-f", "package.556caebd.link",
        "-k", self.alice_pub_path,
        "--verify"
        ], 0)

    # Sign Layout with default gpg key
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-g",
        "-o", "tmp_gpg.layout",
        "--gpg-home", self.gnupg_home
        ], 0)
    # Verify Layout signed with default gpg key
    self.assert_cli_sys_exit([
        "-f", "tmp_gpg.layout",
        "-g", self.default_gpg_keyid,
        "--gpg-home", self.gnupg_home,
        "--verify"
        ], 0)

    # Sign Layout with two gpg keys
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-g", self.gpg_keyid1, self.gpg_keyid2,
        "-o", "tmp_gpg.layout",
        "--gpg-home", self.gnupg_home
        ], 0)
    self.assert_cli_sys_exit([
        "-f", "tmp_gpg.layout",
        "-g", self.gpg_keyid1, self.gpg_keyid2,
        "--gpg-home", self.gnupg_home,
        "--verify"
        ], 0)


  def test_fail_signing(self):
    """Fail signing with an invalid key. """
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", self.carl_path, self.link_path,
        ], 2)


  def test_fail_verification(self):
    """Fail signature verification. """
    # Fail with wrong key (not used for signing)
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", self.carl_pub_path,
        "--verify"
        ], 1)

    # Fail with wrong key (not a valid pub key)
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", self.carl_path,
        "--verify"
        ], 2)

    # Fail with wrong gpg keyid (not used for signing)
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-g", self.default_gpg_keyid,
        "--gpg-home", self.gnupg_home,
        "--verify"
        ], 1)

    # Fail with wrong gpg keyid (not a valid keyid)
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-g", "bogus-gpg-keyid",
        "--gpg-home", self.gnupg_home,
        "--verify"
        ], 2)



  def test_bad_args(self):
    """Fail with wrong combination of arguments. """

    # Conflicting "verify" and signing options (--verify -o)
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", "key-not-used",
        "--verify",
        "-o", "file-not-written"
        ], 2)

    # Conflicting "verify" and signing options (--verify -oa)
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", "key-not-used",
        "--verify",
        "-a",
        ], 2)

    # Wrong "append" option for Link metadata
    self.assert_cli_sys_exit([
        "-f", self.link_path,
        "-k", "key-not-used",
        "-a"
        ], 2)

    # Wrong multiple keys for Link metadata
    self.assert_cli_sys_exit([
        "-f", self.link_path,
        "-k", self.alice_path, self.bob_path,
        ], 2)

    # Wrong number of multiple key types
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", self.alice_path, self.bob_path,
        "-t", "rsa",
        "-o", "tmp.layout",
        ], 2)

    # Wrong multiple gpg keys for Link metadata
    self.assert_cli_sys_exit([
        "-f", self.link_path,
        "-g", self.gpg_keyid1, self.gpg_keyid2,
        ], 2)

    # Only one of gpg or regular key can be passed
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        "-k", self.alice_path,
        "-g"
        ], 2)

    # At least one of gpg or regular key must be passed
    self.assert_cli_sys_exit([
        "-f", self.layout_path,
        ], 2)

    # For verification if gpg option is passed there must be a key id argument
    self.assert_cli_sys_exit([
      "-f", self.layout_path,
      "--verify",
      "-g"
      ], 2)

  def test_bad_metadata(self):
    """Fail with wrong metadata. """

    # Not valid JSON
    self.assert_cli_sys_exit([
        "-f", self.alice_pub_path,
        "-k", "key-not-used",
        ], 2)

    # Valid JSON but not valid Link or Layout
    open("tmp.json", "wb").write(json.dumps({}).encode("utf-8"))
    self.assert_cli_sys_exit([
        "-f", "tmp.json",
        "-k", "key-not-used",
        ], 2)

if __name__ == "__main__":
  unittest.main()
