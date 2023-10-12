pub const ACCEPTED_ETHERTYPES: [[u8; 2]; 3] = [
    [8, 0],     // IPv4
    [134, 221], // IPv6
    [8, 6],     // ARP
                // ... Add others as needed
];

pub const MIN_FRAME_SIZE: usize = 64;
