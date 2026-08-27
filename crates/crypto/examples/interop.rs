use base64::{engine::general_purpose::STANDARD, Engine};
use crypto::{
    aead, build_recipient, open_campaign_keys, unwrap_key, wrap_key, CampaignFile,
    CampaignFileHeader, CampaignKeys, OperatorSecret, SealedBlob, WrappedKey, FORMAT_VERSION,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::json;
use std::io::Read;
use x25519_dalek::StaticSecret;

const SHARED_KEY: [u8; 32] = [0x42; 32];
const CAMPAIGN: &str = "camp_interop";
const FILE_OPERATOR: &str = "op_interop";

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}
fn unb64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("valid base64")
}
fn arr<const N: usize>(s: &str) -> [u8; N] {
    unb64(s)
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes"))
}

fn emit() {
    let plaintext = b"cross-stack crdt update sealed by rust";
    let sealed = aead::seal(&SHARED_KEY, plaintext, CAMPAIGN.as_bytes());
    let op = OperatorSecret::generate();
    let payload = serde_json::to_string(&sealed).unwrap();
    let sig = op.sign(payload.as_bytes());

    let recipient = OperatorSecret::generate();
    let wrap_secret = [0x37u8; 32];
    let wrapped = wrap_key(&wrap_secret, &recipient.public().wrapping);

    let keys = CampaignKeys::generate();
    let file_op = OperatorSecret::generate();
    let header = CampaignFileHeader {
        format_version: FORMAT_VERSION,
        campaign_id: CAMPAIGN.to_string(),
        recipients: vec![build_recipient(
            FILE_OPERATOR,
            &file_op.public(),
            &keys,
            true,
        )],
        snapshot_version: 1,
        key_epoch: 0,
    };
    let snapshot = b"<interop loro snapshot bytes>";
    let sealed_snapshot = keys.seal_content(CAMPAIGN, snapshot);
    let file = CampaignFile {
        header,
        sealed_snapshot,
    };
    let file_bytes = file.encode().unwrap();

    let artifacts = json!({
        "producer": "rust",
        "key_b64": b64(&SHARED_KEY),
        "campaign_id": CAMPAIGN,
        "plaintext_b64": b64(plaintext),
        "sealed": sealed,
        "sign_pub_b64": op.public().signing_b64(),
        "payload": payload,
        "sig_b64": b64(&sig),
        "wrap": {
            "recipient_secret64_b64": b64(&recipient.to_secret_bytes()[..]),
            "wrapped": wrapped,
            "expected_secret_b64": b64(&wrap_secret),
        },
        "file": {
            "operator_id": FILE_OPERATOR,
            "operator_secret64_b64": b64(&file_op.to_secret_bytes()[..]),
            "file_b64": b64(&file_bytes),
            "snapshot_b64": b64(snapshot),
        },
    });
    println!("{}", artifacts);
}

fn check() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let j: serde_json::Value = serde_json::from_str(&input).expect("valid artifacts json");
    let _producer = j["producer"].as_str().unwrap_or("?");

    let key: [u8; 32] = arr(j["key_b64"].as_str().unwrap());
    let aad = j["campaign_id"].as_str().unwrap().as_bytes();
    let sealed: SealedBlob = serde_json::from_value(j["sealed"].clone()).unwrap();
    let opened = aead::open(&key, &sealed, aad).expect("AEAD open must succeed cross-stack");
    assert_eq!(
        opened,
        unb64(j["plaintext_b64"].as_str().unwrap()),
        "plaintext mismatch"
    );

    let pk: [u8; 32] = arr(j["sign_pub_b64"].as_str().unwrap());
    let sig: [u8; 64] = arr(j["sig_b64"].as_str().unwrap());
    let vk = VerifyingKey::from_bytes(&pk).expect("valid verifying key");
    vk.verify(
        j["payload"].as_str().unwrap().as_bytes(),
        &Signature::from_bytes(&sig),
    )
    .expect("Ed25519 signature must verify cross-stack");

    let w = &j["wrap"];
    let recip_bytes: [u8; 64] = arr(w["recipient_secret64_b64"].as_str().unwrap());
    let recip_x25519 = StaticSecret::from(<[u8; 32]>::try_from(&recip_bytes[32..]).unwrap());
    let wrapped: WrappedKey = serde_json::from_value(w["wrapped"].clone()).unwrap();
    let unwrapped =
        unwrap_key(&wrapped, &recip_x25519).expect("key unwrap must succeed cross-stack");
    assert_eq!(
        unwrapped.to_vec(),
        unb64(w["expected_secret_b64"].as_str().unwrap()),
        "unwrapped secret mismatch"
    );

    let f = &j["file"];
    let op_id = f["operator_id"].as_str().unwrap();
    let op_bytes: [u8; 64] = arr(f["operator_secret64_b64"].as_str().unwrap());
    let op_secret = OperatorSecret::from_secret_bytes(&op_bytes);
    let file_bytes = unb64(f["file_b64"].as_str().unwrap());
    let decoded = CampaignFile::decode(&file_bytes).expect("campaign file must decode cross-stack");
    let recovered = open_campaign_keys(&decoded.header, op_id, &op_secret)
        .expect("operator must recover campaign keys cross-stack");
    let snapshot = recovered
        .open_content(&decoded.header.campaign_id, &decoded.sealed_snapshot)
        .expect("snapshot must open under the recovered campaign key");
    assert_eq!(
        snapshot,
        unb64(f["snapshot_b64"].as_str().unwrap()),
        "snapshot mismatch"
    );

    println!("rust-check: ok");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("emit") => emit(),
        Some("check") => check(),
        _ => {
            eprintln!("usage: interop <emit|check>");
            std::process::exit(2);
        }
    }
}
