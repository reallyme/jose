// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn schema_operations_match_every_sdk_binary_and_json_fixture(
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct Corpus {
        cases: Vec<Vector>,
    }
    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        request_json: String,
        request_hex: String,
        response_hex: String,
    }
    fn decode(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|[first, second]| {
                let digits = [char::from(*first), char::from(*second)]
                    .iter()
                    .collect::<String>();
                u8::from_str_radix(&digits, 16)
            })
            .collect()
    }
    let corpus: Corpus =
        serde_json::from_str(include_str!("../../../../vectors/schema-operations.json"))?;
    assert_eq!(corpus.cases.len(), 24);
    for vector in corpus.cases {
        let binary = zeroize::Zeroizing::new(decode(&vector.request_hex)?);
        let expected = zeroize::Zeroizing::new(decode(&vector.response_hex)?);
        let binary_response =
            reallyme_jose::wire::execute_operation_v1(&binary, &mut FixedRandom::new([1; 12]));
        let json_response = reallyme_jose::wire::execute_operation_json_v1(
            vector.request_json.as_bytes(),
            &mut FixedRandom::new([1; 12]),
        );
        assert_eq!(binary_response, expected, "{} binary", vector.name);
        assert_eq!(json_response, expected, "{} JSON", vector.name);
    }
    Ok(())
}
