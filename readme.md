# Post-Quantum Cryptography TLS Handshake Benchmark Suite

This project provides a comprehensive benchmarking suite for testing various post-quantum cryptography (PQC) algorithms in TLS handshakes. It supports testing different Key Encapsulation Mechanism (KEM) and signature algorithms, with configurable network conditions.

## Features

- Benchmark multiple PQC algorithms including:
  - KEMs: Kyber, MLKEM, BIKE, HQC, Frodo, and classical algorithms
  - Signatures: Dilithium, SPHINCS+, Falcon, MAYO, and classical algorithms
- Network condition simulation (packet loss, bandwidth limitation)
- Detailed performance metrics:
  - Handshake time
  - Memory usage
  - CPU utilization
  - Success/failure rates
- Automated result analysis with visualizations
- Support for hybrid classical-PQC combinations

## Requirements

### System Requirements
- Linux-based operating system (tested on Ubuntu 20.04+)
- Root/sudo privileges (required for network namespace operations)
- Python 3.8 or higher

### Python Dependencies
```
pip install -r requirements.txt
```

Required packages:
- psutil>=5.9.0
- matplotlib>=3.5.0
- seaborn>=0.11.0
- pandas>=1.3.0
- numpy>=1.21.0
- pyyaml>=5.4.0

### OpenSSL Requirements
- Custom OpenSSL build with oqsprovider support
- OpenSSL version 3.0.0 or higher
- oqsprovider installed and configured

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/pqc-tls-benchmark.git
cd pqc-tls-benchmark
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure OpenSSL with oqsprovider is properly installed:
```bash
export OPENSSL_PATH="/usr/local/ssl/bin/openssl"
```

## Configuration

The benchmark suite uses YAML configuration files to specify algorithms and network conditions. Example configuration:

```yaml
algorithms:
  kem:
   - x25519
   - kyber512
   - mlkem768
  sig:
   - ed25519
   - dilithium2
   - falcon512

network_settings:
  packet_loss: 10        # percentage
  bandwidth: 10mbit      # bandwidth limit
  interface: veth0       # network interface
```

## Usage

### Single Benchmark Run

```bash
sudo python3 benchmark.py config.yml
```

### Batch Benchmarking

```bash
sudo ./script.sh
```

This will run benchmarks for all configuration files in the `loop` directory.

## Output and Results

Results are saved in the `results` directory with the following structure:
```
results/
├── [config_name]/
│   ├── performance_statistics.csv
│   ├── handshake_error_statistics.png
│   ├── avg_handshake_time.png
│   ├── avg_memory_usage.png
│   ├── avg_cpu_usage.png
│   └── [algorithm]_results.txt
```

Each benchmark generates:
- Detailed performance metrics
- Error statistics
- Visualization plots
- Raw data in CSV format

## Architecture

The suite consists of several key components:
- `benchmark.py`: Main benchmarking orchestrator
- `client.py`: TLS client implementation
- `server.py`: TLS server implementation
- `utility.py`: Helper functions and analysis tools
- `script.sh`: Batch processing script

## Network Setup

The benchmark uses Linux network namespaces to create isolated network environments:
- Creates server_ns and client_ns namespaces
- Configures virtual ethernet (veth) pairs
- Applies network conditions (packet loss, bandwidth limits)

## Troubleshooting

Common issues and solutions:

1. Permission Errors
```bash
sudo chmod +x script.sh
sudo python3 benchmark.py config.yml
```

2. Network Namespace Issues
```bash
# Clean up existing namespaces
sudo ip netns delete server_ns
sudo ip netns delete client_ns
```

3. OpenSSL Provider Issues
```bash
# Verify OpenSSL providers
$OPENSSL_PATH list -providers
```

## Version History

- v1.0.0 (2025-01)
  - Initial release
  - Support for basic PQC algorithms
  - Network condition simulation
  - Performance metrics collection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OpenQuantumSafe project for oqsprovider
- OpenSSL team
- Contributors and testers

## Contact

For questions and support, please open an issue in the GitHub repository.
