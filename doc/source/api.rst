API
===

The in-toto API provides various functions and :doc:`classes <model>` that you
can use to generate, consume, modify and verify in-toto metadata, as a more
feature-rich, programmable alternative to the :doc:`command line tools
<command-line-tools/index>`.

.. note::

   **Cryptographic Signatures**

   in-toto metadata is signed with cryptographic keys using the in-house crypto
   library `securesystemslib <https://github.com/secure-systems-lab/securesystemslib>`_
   Please refer to its `documentation <https://python-securesystemslib.readthedocs.io/en/latest/signer.html>`_
   for details about loading a `Signer` for "Evidence Generation".

   Loading verification keys for "Supply Chain Verification" is
   documented `in-toto#663 <https://github.com/in-toto/in-toto/issues/663>`_.



Evidence Generation
-------------------

.. autofunction:: in_toto.runlib.in_toto_run
.. autofunction:: in_toto.runlib.in_toto_record_start
.. autofunction:: in_toto.runlib.in_toto_record_stop
.. autofunction:: in_toto.runlib.in_toto_match_products


Supply Chain Verification
-------------------------

.. autofunction:: in_toto.verifylib.in_toto_verify
