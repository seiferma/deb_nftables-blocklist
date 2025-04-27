# Debian Repository of nftables-blocklist

The repository contains deb packages for the releases of [nftables-blocklist](https://github.com/seiferma/deb_nftables-blocklist).
To make use of the repository, follow the steps below.

# Prerequisites
* `curl`
* `sudo`

# Installation
* Import the signing key of the repository
```sh
sudo curl -fsSL https://seiferma.github.io/deb_nftables-blocklist/pubkey.gpg -o /etc/apt/keyrings/nftables-blocklist.asc
```

* Add the repository to the sources of apt
```sh
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/nftables-blocklist.asc] https://seiferma.github.io/deb_nftables-blocklist all main" | \
  sudo tee /etc/apt/sources.list.d/nftables-blocklist.list > /dev/null
```

* Update the package cache and install `nftables-blocklist`
```sh
apt-get update
apt-get install nftables-blocklist
```