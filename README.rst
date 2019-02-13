cloudflare-cli-py
================================================================================

CLI Usage
--------------------------------------------------------------------------------

Tool installs as ``xdx-cloudflare``.

* Credentials can be provides with 
    * Command line arguments ``--email EMAIL`` and ``--token TOKEN``
    * Environment variables ``XADIX_CLOUDFLARE_EMAIL=EMAIL`` and ``XADIX_CLOUDFLARE_TOKEN=TOKEN``

Example usage:

.. code-block:: bash

    xdx-cloudflare domain record -d csys.eu.org list
    xdx-cloudflare domain record -d csys.eu.org upsert -n foofies.csys.eu.org -t A -x 1 -v 127.8.2.1

