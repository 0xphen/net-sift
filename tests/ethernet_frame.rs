use net_sift::protocols::{
    errors::ParserError,
    ethernet_frame::{EtherType, EthernetFrame},
};

const MOCK_MALFORMED_ETHERNET_FRAME: [u8; 28] = [
    12, 25, 60, 255, 88, 12, 108, 100, 19, 25, 200, 199, 81, 0, 2, 22, 8, 0, 12, 16, 17, 2, 90, 20,
    2, 22, 1, 8,
];

const DEFAULT_DEST_MAC: [u8; 6] = [12, 25, 60, 255, 88, 12];
const DEFAULT_SRC_MAC: [u8; 6] = [108, 100, 19, 25, 200, 199];
const DEFAULT_ETHER_TYPE: [u8; 2] = [134, 221];
const INVALID_ETHER_TYPE: [u8; 2] = [99, 0];
const DEFAULT_FCS: [u8; 4] = [1, 2, 3, 4];
const DEFAULT_Q_TAG: [u8; 4] = [129, 0, 2, 22];

fn generate_mock_frame(
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: [u8; 2],
    q_tag: Option<[u8; 4]>,
    fcs: [u8; 4],
) -> [u8; 64] {
    let mut frame = [0u8; 64];

    frame[0..6].copy_from_slice(&dest_mac);
    frame[6..12].copy_from_slice(&src_mac);
    match q_tag {
        Some(v) => {
            frame[12..16].copy_from_slice(&v);
            frame[16..18].copy_from_slice(&ether_type);
        }
        _ => frame[12..14].copy_from_slice(&ether_type),
    }

    frame[(64 - 4)..64].copy_from_slice(&fcs);
    frame
}

fn validate_ethernet_frame(frame: EthernetFrame, expected_values: &EthernetFrameValues) {
    assert_eq!(
        frame.mac_destination.to_string(),
        expected_values.expected_mac_destination_string
    );
    assert_eq!(
        frame.mac_destination.0,
        expected_values.expected_mac_destination
    );

    assert_eq!(
        frame.mac_source.to_string(),
        expected_values.expected_mac_source_string
    );
    assert_eq!(frame.mac_source.0, expected_values.expected_mac_source);

    assert_eq!(frame.ether_type, expected_values.expected_ether_type);
    assert_eq!(frame.q_tag, expected_values.expected_q_tag);
    assert_eq!(frame.payload, expected_values.expected_payload);
}

struct EthernetFrameValues {
    expected_mac_destination_string: &'static str,
    expected_mac_destination: [u8; 6],
    expected_mac_source_string: &'static str,
    expected_mac_source: [u8; 6],
    expected_ether_type: EtherType,
    expected_q_tag: Option<u32>,
    expected_payload: &'static [u8],
}

#[test]
fn can_create_ethernet_frame_without_qtag() {
    let frame = generate_mock_frame(
        DEFAULT_DEST_MAC,
        DEFAULT_SRC_MAC,
        DEFAULT_ETHER_TYPE,
        None,
        DEFAULT_FCS,
    );

    let ethernet_frame = EthernetFrame::new(&frame).unwrap();

    let expected_values = EthernetFrameValues {
        expected_mac_destination_string: "0C:19:3C:FF:58:0C",
        expected_mac_destination: DEFAULT_DEST_MAC,
        expected_mac_source_string: "6C:64:13:19:C8:C7",
        expected_mac_source: DEFAULT_SRC_MAC,
        expected_ether_type: EtherType::from(u16::from_be_bytes(DEFAULT_ETHER_TYPE)),
        expected_q_tag: None,
        expected_payload: &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    };

    validate_ethernet_frame(ethernet_frame, &expected_values);
}

#[test]
fn can_create_ethernet_frame_with_qtag() {
    let frame = generate_mock_frame(
        DEFAULT_DEST_MAC,
        DEFAULT_SRC_MAC,
        DEFAULT_ETHER_TYPE,
        Some(DEFAULT_Q_TAG),
        DEFAULT_FCS,
    );
    let ethernet_frame = EthernetFrame::new(&frame).unwrap();

    let expected_values = EthernetFrameValues {
        expected_mac_destination_string: "0C:19:3C:FF:58:0C",
        expected_mac_destination: DEFAULT_DEST_MAC,
        expected_mac_source_string: "6C:64:13:19:C8:C7",
        expected_mac_source: DEFAULT_SRC_MAC,
        expected_ether_type: EtherType::from(u16::from_be_bytes(DEFAULT_ETHER_TYPE)),
        expected_q_tag: Some(2164261398),
        expected_payload: &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    };

    validate_ethernet_frame(ethernet_frame, &expected_values);
}

#[test]
fn fails_if_bad_ether_type() {
    let frame = generate_mock_frame(
        DEFAULT_DEST_MAC,
        DEFAULT_SRC_MAC,
        INVALID_ETHER_TYPE,
        None,
        DEFAULT_FCS,
    );
    let result = EthernetFrame::new(&frame);

    assert!(matches!(result, Err(ParserError::InvalidEtherType)))
}

#[test]
fn fails_if_frame_is_malformed() {
    let result = EthernetFrame::new(&MOCK_MALFORMED_ETHERNET_FRAME);

    let malformed_frame_size = MOCK_MALFORMED_ETHERNET_FRAME.to_vec().len();

    assert!(matches!(
        result,
        Err(ParserError::FrameTooShort(malformed_frame_size, 64))
    ));
}
