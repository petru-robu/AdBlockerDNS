# AdBLocker

## Dependencies
- CMake - Build system
- Boost.Asio UDP/TCP networking

```bash
# Install boost with:
sudo dnf install boost-devel
sudo apt install libboost-all-dev
```

## Building

To run this project, install cmake and boost and then run:
```bash
# to build
cmake -S . -B build
cmake --build build

# to run build
./build/dns-resolver 

# to clear cache
rm -rf build
```

## Testing the DNS
Start the server:
```bash
./build/dns-resolver 
```

From another term:
```bash
dig @127.0.0.1 -p 5300 example.com A
```