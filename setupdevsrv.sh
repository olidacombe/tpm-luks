#!/bin/bash

set -xeuo pipefail

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 0/0 -j ACCEPT
iptables -P INPUT DROP
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install cargo-watch

# to run cargo test in https://github.com/parallaxsecond/rust-tss-esapi
apt-get update
apt-get install \
	build-essential \
	docker.io \
	iptables-persistent \
	libtss2-dev tss2 \
	pkg-config \
	swtpm{,-tools}

iptables -I DOCKER-USER -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I DOCKER-USER -i bond0 ! -s 127.0.0.1 -j DROP

iptables-save > /etc/iptables/rules.v4
