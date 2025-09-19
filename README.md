# Fox High Speed TLS Signature Filtering

High speed TLS based filtering able to run entirely in an eBPF filter.

# Example Usage

Generate a config file
```
./generate-config block-curl.fconf blacklist signatures/curl-8.15.0-arch.bin
```

Load the filter on to a network device
```
sudo ./fox-filter block-curl.fconf wlan0 fox.bpf
```

