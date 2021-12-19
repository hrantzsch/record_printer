use std::io;

use tls_parser::nom::Err;
use tls_parser::*;

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn show(v: &[(String, String)]) {
    v.iter().for_each(|(name, value)| {
        println!("{}\t{}", value, name);
    })
}

fn nyi_token() -> (String, String) {
    ("nyi".to_string(), String::new())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn serialize_ciphers(ciphers: &[TlsCipherSuiteID]) -> Vec<(String, String)> {
    let mut result = vec![(
        format!("Ciphersuites Length ({})", ciphers.len()),
        format!("{:04X}", ciphers.len() * 2),
    )];
    for c in ciphers {
        result.push((
            format!(
                "- {}",
                c.get_ciphersuite().map_or_else(|| "Unknown", |c| c.name)
            ),
            format!("{:04X}", c.0),
        ));
    }
    result
}

fn serialize_ext(ext: &[u8]) -> Vec<(String, String)> {
    match parse_tls_extension(ext) {
        Err(_) => vec![],
        Ok((rem, e)) => {
            let mut v = vec![(
                format!("- {:?}", e),
                bytes_to_hex(&ext[0..ext.len() - rem.len()]),
            )];
            v.append(&mut serialize_ext(rem));
            v
        }
    }
}

fn serialize_exts(ext: Option<&[u8]>) -> Vec<(String, String)> {
    ext.map_or_else(Vec::new, |exts| {
        let mut result = vec![(
            format!("Extensions Length ({})", exts.len()),
            format!("{:02X}", exts.len()),
        )];
        result.append(&mut serialize_ext(exts));
        result
    })
}

fn serialize_msg_handshake(hs: TlsMessageHandshake) -> Vec<(String, String)> {
    match hs {
        TlsMessageHandshake::ClientHello(hello) => {
            let mut content = vec![(
                format!("{}", hello.version),
                format!("{:04X}", hello.version.0),
            )];

            content.push((
                format!("rand_time ({})", hello.rand_time),
                format!("{:08X}", hello.rand_time),
            ));

            content.push(("rand_data".to_string(), bytes_to_hex(hello.rand_data)));

            if let Some(s_id) = hello.session_id {
                content.push((
                    "Session ID Length".to_string(),
                    format!("{:02X}", s_id.len()),
                ));
                content.push(("Session ID".to_string(), bytes_to_hex(s_id)));
            } else {
                content.push(("Session ID Length".to_string(), "00".to_string()));
            }

            content.append(&mut serialize_ciphers(&hello.ciphers));

            content.push((
                format!("Compression Methods Length ({})", hello.comp.len()),
                format!("{:02X}", hello.comp.len()),
            ));
            for c in &hello.comp {
                content.push((format!("- {}", c.0), format!("{:04X}", c.0)));
            }

            content.append(&mut serialize_exts(hello.ext));

            let mut result = vec![("Type (client hello)".to_string(), "01".to_string())];
            let content_bytes = content
                .iter()
                .map(|v| v.1.clone())
                .collect::<String>()
                .len()
                / 2;
            result.push((
                format!("Client Hello Length ({})", content_bytes),
                format!("{:06X}", content_bytes),
            ));

            result.append(&mut content);
            result
        }

        _ => vec![nyi_token()],
    }
}

fn serialize_header(hdr: TlsRecordHeader) -> Vec<(String, String)> {
    vec![
        (
            format!("{}", hdr.record_type),
            format!("{:02X}", hdr.record_type.0),
        ),
        (format!("{}", hdr.version), format!("{:04X}", hdr.version.0)),
        (format!("Length ({})", hdr.len), format!("{:04X}", hdr.len)),
    ]
}
fn serialize_record(record: &[u8]) -> Vec<(String, String)> {
    match parse_tls_plaintext(record) {
        Ok((_, TlsPlaintext { hdr, msg })) => {
            let mut result = serialize_header(hdr);

            for m in msg {
                let mut r = match m {
                    TlsMessage::Handshake(hs) => serialize_msg_handshake(hs),
                    _ => vec![nyi_token()],
                };
                result.append(&mut r);
            }

            result
        }
        Err(Err::Incomplete(_)) => {
            panic!("Incomplete record");
        }
        Err(e) => {
            panic!("Failed parsing record: {:?}", e);
        }
    }
}

fn main() {
    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .expect("Failed to read line");

    let trimmed: String = strip_whitespace(&buffer);
    show(&serialize_record(
        &hex::decode(trimmed).expect("Decoding failed")[..],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run_test(encoded: &str) {
        let stripped = strip_whitespace(encoded);
        let result = serialize_record(&hex::decode(&stripped).unwrap());
        show(&result[..]);
        assert_eq!(
            stripped.to_ascii_uppercase(),
            result.into_iter().map(|v| v.1).collect::<String>(),
        );
    }

    #[test]
    fn rfc8448_test() {
        run_test(
            "16030100c4010000c00303cb                   \
             34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912 \
             ec18a2ef6283024dece70000061301130313020100 \
             00910000000b0009000006736572766572ff010001 \
             00000a00140012001d001700180019010001010102 \
             0103010400230000003300260024001d002099381d \
             e560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d \
             5413691e529aaf2c002b0003020304000d0020001e \
             040305030603020308040805080604010501060102 \
             010402050206020202002d00020101001c00024001",
        );
    }

    #[test]
    fn illustrated_tls_test() {
        // Example record from "Illustrated TLS Connection" https://tls13.ulfheim.net,
        // published unter the MIT License.

        // MIT License

        // Copyright (c) 2018 Michael Driscoll

        // Permission is hereby granted, free of charge, to any person obtaining a copy
        // of this software and associated documentation files (the "Software"), to deal
        // in the Software without restriction, including without limitation the rights
        // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        // copies of the Software, and to permit persons to whom the Software is
        // furnished to do so, subject to the following conditions:

        // The above copyright notice and this permission notice shall be included in all
        // copies or substantial portions of the Software.

        // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        // SOFTWARE.

        run_test(
            "16030100ca010000c60303000102030405060708090a0b0c0d0e0f1011 \
             12131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebeced \
             eeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000 \
             770000001800160000136578616d706c652e756c666865696d2e6e6574 \
             000a00080006001d00170018000d001400120403080404010503080505 \
             01080606010201003300260024001d0020358072d6365880d1aeea329a \
             df9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b00 \
             03020304",
        );
    }
}
