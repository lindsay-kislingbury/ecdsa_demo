# Bitcoin Signature Demo: ECDSA vs DSA

This demo illustrates why Bitcoin's use of ECDSA over traditional DSA enables a more scalable blockchain. With public keys nearly 37x smaller and faster verification, ECDSA saves the Bitcoin network hundreds of megabytes daily in storage requirements while maintaining equivalent security.

## Requirements

- Python 3.8 or higher
- tkinter (usually comes with Python)
- cryptography library

## Installation

1. Make sure you have Python installed:

   ```
   python --version
   ```

2. Install the required cryptography library:

   ```
   pip install cryptography
   ```

3. Clone this repository or download the files:
   ```
   git clone https://github.com/yourusername/ecdsa_demo.git
   cd ecdsa_demo
   ```

## Running the Demo

Run the demo with:

```
python ecdsa_demo.py
```

## Features

- Generates ECDSA and DSA keys
- Signs and verifies messages with both algorithms
- Shows key sizes and signature lengths
- Measures performance differences
- Simulates Bitcoin block validation speeds

## How to Use

1. Launch the application
2. Click "New Hash" to generate a new message hash
3. Click "Sign" to create signatures with both algorithms
4. Click "Verify" to test signature verification
5. Compare the results in the bottom panel

## Technical Details

- Uses secp256k1 curve (Bitcoin's curve)
- ECDSA: 256-bit keys
- DSA: 3072-bit keys (comparable security level)
- Simulates 1000 operations per test

## Troubleshooting

If you see "tkinter not found":

- Windows: Reinstall Python with "tcl/tk" option checked
- Linux: `sudo apt-get install python3-tk`
- macOS: Use Python.org installer instead of Homebrew

## License

MIT License - Feel free to use and modify
