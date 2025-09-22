# Fox's High Speed TLS Signature Filtering

High speed TLS based filtering able to run entirely in an eBPF filter.

## Requirements

- Linux 6.12.43+
- libpbf and libxdp

## How does it work 

Instead of taking the full [JA4 hash](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) to fingerprint traffic which is slow to calculate and is hard to implement in a BPF filter, I take a [Jenkins hash](https://en.wikipedia.org/wiki/Jenkins_hash_function) of the sorted supported ciphers in any given TLS request. To similar effect as JA4, keeping fingerprinting usefulness. Switching to a non-cryptographic hashing algorithm is okay here because any given attacker with enough skill could replicate the ciphers of another client, so any hash reversing would be useless or  at best force the attacker to implement a different amount of hashes.

# Example Usage

Generate a config file
```
./generate-config block-curl.fconf blacklist signatures/curl-8.15.0-arch.bin
```

Load the filter on to a network device
```
sudo ./fox-filter block-curl.fconf wlan0 fox.bpf
```

