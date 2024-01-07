# ARC-72

This is the AVM smart contract that powers High Forge.

## Usage

The smart contract is built using [PyTeal](https://pyteal.readthedocs.io/en/stable/overview.html).

Make sure you have the dependencies of the project installed:

```bash
pip install -r requirements.txt
```

Then you are able to compile the smart contract:

```bash
python3 arc72.py
```

Outputs will go into the arc72/{version}/ folder.

- The \*.b64 files are Base64-encoded representations of the compiled contract.
- The \*.bin files are the binary versions of the compiled contract.
- The \*.teal files are the uncompiled TEAL output.
