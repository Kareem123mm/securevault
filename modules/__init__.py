"""
This file initializes the 'modules' package, making its modules available for import.

It explicitly imports all the core cryptographic and networking modules,
allowing them to be accessed using 'from modules import ...' syntax.

This setup supports two import styles:
1. Direct import after path modification:
   import sys
   sys.path.insert(0, 'modules')
   import elgamal

2. Package-style import:
   from modules import elgamal
"""

from . import elgamal
from . import rc6
from . import xtea
from . import ca
from . import server
from . import client
from . import handshake
from . import key_manager
from . import elgamal_utils

if __name__ == "__main__":
    # Test to confirm all modules can be loaded
    import elgamal, rc6, xtea, ca, server, client, handshake, key_manager, elgamal_utils
    print("Successfully imported:", elgamal.__name__)
    print("Successfully imported:", rc6.__name__)
    print("Successfully imported:", xtea.__name__)
    print("Successfully imported:", ca.__name__)
    print("Successfully imported:", server.__name__)
    print("Successfully imported:", client.__name__)
    print("Successfully imported:", handshake.__name__)
    print("Successfully imported:", key_manager.__name__)
    print("Successfully imported:", elgamal_utils.__name__)
