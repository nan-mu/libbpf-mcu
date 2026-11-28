# Firewall

The XDP classifier checks for an Ethernet IPv4 packet. It looks up the IPv4 source in the 256-entry `blacklist` HASH map with u32 keys and values. A hit increments the counter and returns `XDP_DROP`. Other packets return `XDP_PASS`.

Build the portable modes with `cargo run --locked -p mcu -- build -c firewall`.
