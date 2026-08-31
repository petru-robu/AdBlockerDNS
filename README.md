# AdBlocker

**AdBlockerDNS** is a C++20 DNS resolver that runs locally on UDP port `5300`

- It parses DNS packets, performs recursive DNS resolution starting from root servers, and returns real DNS answers.

- It blocks domains listed in `res/blocklist.txt` by returning `NXDOMAIN`, including for subdomains.

- It supports plain domain lists and hosts-file style blocklists, with a small test suite focused on blocklist behavior.


<!-- <img src="./forbidden.webp" alt="forbidden.webp" width="35%" /> -->

## Blocking

Domains in `res/blocklist.txt` return `NXDOMAIN` without being sent to
upstream DNS servers. An entry also blocks all of its subdomains.

Both plain-domain and hosts-file formats are accepted:

```text
doubleclick.net
0.0.0.0 ads.example.com tracker.example.com
```

The blocklist is loaded when the server starts, so restart the server after
editing it.

```bash
dig @127.0.0.1 -p 5300 subdomain.doubleclick.net A
```

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
