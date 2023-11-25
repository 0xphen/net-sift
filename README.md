# net-sift

This library offers an efficient and adaptable network packet parser, with a minimal reliance on external dependencies. It is designed to parse and verify an extensive array of essential network protocols, including ethernet frames, IPv4, IPv6, UDP, TCP, among others. The focus of development is centered on the dominant protocols found in the internet and transport layers.

## Supported Protocols:
## Protocols

- [X] ethernet
- [X] ipv4
- [X] ipv6
- [X] tcp
- [X] udp
- [X] icmp
- [ ] http
- [ ] tls
- [ ] dns
- [ ] dhcp
- [ ] arp

## Building
To install the latest version of `net-sift`, ensure you have [Rust toolchain installed](https://rustup.rs/), then run:
```
cargo install net-sift
```
Or, to build from source (binary in `target/release/net-sift`):
```
cargo build --release
```

## Usage
Net-sift supports both shallow packet parsing (decoding standalone network protocols), and deep packet inspection (parsing and decoding layered network hierarchies).

### Shallow Packet Parsing
Net-sift provides shallow packet parsing, by decoding the basic structure of network protocols; it dissects packets to reveal fundamental fields. This parsing is limited to the immediate protocol layer without delving into nested protocols. Net-sift's parsing capability is suitable for applications needing quick access to outer packet information.

##### Example parsing an ethernet frame
```rust
use net_sift::parsers::{ethernet_frame::EthernetFrame, errors::ParserError};

// A function that attempts to parse an Ethernet frame from a slice of bytes.
fn shallow_parse_ether_frame(packet_data: &[u8]) -> Result<EthernetFrame, ParserError> {
    let fcs_enabled = true;
    EthernetFrame::from_bytes(packet_data, fcs_enabled)
}

fn main() {
    // Sample raw Ethernet frame data
    let raw_data: Vec<u8> = vec![
        // Your raw Ethernet frame bytes here
    ];

    // Attempt to parse the raw data as an Ethernet frame
    match shallow_parse_ether_frame(&raw_data) {
        Ok(frame) => println!("Parsed Ethernet Frame: {:?}", frame),
        Err(e) => eprintln!("Failed to parse Ethernet Frame: {:?}", e),
    }
}

```

### Deep Packet Inspection
Net-sift extends its parsing capabilities to deep packet inspection, meticulously analyzing embedded network layers within a packet. It interprets not just the Ethernet frame but also examines encapsulated protocols like IPv4, IPv6, TCP, and UDP. This thorough analysis aids in a comprehensive understanding of the packet's journey and its various interactions across network boundaries, making it ideal for in-depth network analysis and troubleshooting.

##### Example parsing an ethernet frame

```rust
use net_sift::parsers::{ethernet_frame::EthernetFrame, errors::ParserError, definitions::{DeepParser, LayeredData}};

// A function that attempts to parse an Ethernet frame and all embedded packets
fn deep_parse_ether_frame(packet_data: &[u8]) -> Result<LayeredData, ParserError> {
    let fcs_enabled = true;
    let ether_frame = EthernetFrame::from_bytes(packet_data, fcs_enabled)?;
    ether_frame.parse_next_layer()
}

fn main() {
    // Sample raw Ethernet frame data
    let raw_data: Vec<u8> = vec![
        // Example bytes of an Ethernet frame
    ];

    // Attempt to recursively parse all layered protocols
    match deep_parse_ether_frame(&raw_data) {
        Ok(layered_data) => {
            println!("Parsed Layered Data: {:?}", layered_data);
        },
        Err(e) => {
            eprintln!("Failed to parse the Ethernet Frame and embedded layers: {:?}", e);
        },
    }
}

```

