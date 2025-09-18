# BTC Puzzle Cracker Python 🚀

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Stars](https://img.shields.io/github/stars/itsdstar/BTC_Puzzle_Cracker_Python?style=social)

A high-performance Bitcoin puzzle cracker written in Python with both CPU and GPU acceleration support. This tool attempts to solve Bitcoin puzzle challenges by generating private keys within specified ranges and checking for matching Bitcoin addresses.

## 🎯 What is Bitcoin Puzzle?

Bitcoin puzzles are challenges where Bitcoin addresses with known balances are created from private keys within specific ranges. The goal is to find the correct private key that generates the known Bitcoin address. These puzzles serve as both cryptographic challenges and demonstrations of Bitcoin's security.

## ⚠️ Important Disclaimer

**Educational Purpose Only**: This tool is created for educational and research purposes. The Bitcoin puzzles are designed to demonstrate the security of Bitcoin's cryptography and the computational difficulty of brute-force attacks.

- **Legal Use Only**: Only use this on puzzle addresses that are intentionally created for solving
- **Not for Illegal Activities**: Do not use this tool to attempt unauthorized access to Bitcoin wallets
- **Security Research**: This is a legitimate cryptographic research tool

## 🚀 Features

- **CPU Implementation**: Multi-threaded brute force approach
- **GPU Acceleration**: CUDA-powered parallel processing (GPUv.py)
- **Heatmap Analysis**: Visual analysis of key distribution patterns
- **Memory Efficient**: Optimized algorithms for large key ranges
- **Progress Tracking**: Real-time progress monitoring
- **Multiple Approaches**: Different strategies for key generation and checking

## 📋 Requirements

### System Requirements
- Python 3.8+
- For GPU version: NVIDIA GPU with CUDA support
- Sufficient RAM (varies by range size)

### Dependencies

```bash
pip install ecdsa base58 pycryptodome numpy bloom-filter psutil numba matplotlib seaborn
```

### CUDA Installation (for GPU version)
For GPU acceleration, install NVIDIA CUDA Toolkit:
- Download from [NVIDIA CUDA Toolkit](https://developer.nvidia.com/cuda-downloads)
- Follow installation instructions for your operating system

## 🔧 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/itsdstar/BTC_Puzzle_Cracker_Python.git
   cd BTC_Puzzle_Cracker_Python
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Or use the provided command:
   ```bash
   pip install ecdsa base58 pycryptodome numpy bloom-filter psutil numba matplotlib seaborn
   ```

3. **For GPU support (optional):**
   - Install NVIDIA CUDA Toolkit
   - Verify CUDA installation: `nvcc --version`

## 🎮 Usage

### Basic CPU Usage

```bash
python puzzle66.py
```

This will start searching for Puzzle #66 within the specified range.

### GPU Accelerated Version

```bash
python GPUv.py
```

### Heatmap Analysis

```bash
python heatmap.py
```

Generates visual analysis of key distribution patterns.

### Custom Range Search

Modify the range variables in the Python files:

```python
start_range = 0x2000000000000000  # Start of Puzzle #66 range
end_range = 0x3FFFFFFFFFFFFFFF    # End of Puzzle #66 range
known_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Target address
```

## 📁 File Structure

```
BTC_Puzzle_Cracker_Python/
├── puzzle66.py          # Main CPU implementation
├── GPUv.py             # GPU accelerated version
├── heatmap.py          # Heatmap analysis tool
├── improvement.py      # Enhanced algorithms
├── RMD160.py          # RIPEMD160 hash implementation
├── heatmap.pkl        # Precomputed heatmap data
├── pip_commands.txt   # Dependency list
└── README.md         # This file
```

## 🔬 How It Works

1. **Key Generation**: Generates private keys within the specified range
2. **Address Derivation**: Converts private keys to Bitcoin addresses using:
   - ECDSA elliptic curve cryptography
   - SHA-256 hashing
   - RIPEMD-160 hashing
   - Base58 encoding
3. **Address Matching**: Compares generated addresses with the target
4. **Result Output**: Reports the private key if a match is found

## 📊 Performance

- **CPU Version**: ~10,000-50,000 keys/second (depends on hardware)
- **GPU Version**: ~100,000-1,000,000+ keys/second (depends on GPU)
- **Memory Usage**: Optimized for minimal RAM consumption

## 🎯 Current Puzzle Status

This implementation focuses on **Puzzle #66**:
- **Range**: `2^65` to `2^66-1`
- **Address**: `13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so`
- **Prize**: 6.6 BTC (as of last update)
- **Status**: Unsolved

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Areas for improvement:

- Algorithm optimization
- Additional GPU implementations
- Better memory management
- Enhanced visualization tools
- Performance benchmarking

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚡ Performance Tips

1. **Use GPU version** for maximum speed
2. **Adjust thread count** based on your CPU cores
3. **Monitor memory usage** for large ranges
4. **Use SSD storage** for better I/O performance
5. **Keep system cool** during intensive operations

## 🔗 Related Projects

- [Bitcoin Puzzles List](https://bitcoinpuzzle.info/)
- [Puzzle Challenge Website](https://bitcoin-puzzle.com/)
- [Bitcoin Developer Documentation](https://developer.bitcoin.org/)

## 📞 Support

If you have questions or need help:

1. Check existing [Issues](https://github.com/itsdstar/BTC_Puzzle_Cracker_Python/issues)
2. Create a new issue for bugs or feature requests
3. Join discussions in the [Discussions](https://github.com/itsdstar/BTC_Puzzle_Cracker_Python/discussions) tab

## 🌟 Star History

If you find this project useful, please consider giving it a star! ⭐

---

**Happy Puzzle Solving!** 🧩

*Remember: The real treasure is the cryptographic knowledge we gained along the way.* 😄