//! A deposit built by the phone app's Java crypto (`android/src/.../Crypto.java`)
//! must open in the Rust intake. Two fixtures: `java-deposit.json` from a desktop
//! JDK, and `android-deposit.json` from a real Android runtime (emulator, with the
//! device key held in the Android keystore). Both come from
//! `android/test/.../InteropMain.java`; `created` is fixed, so the test opens each
//! "at" that moment rather than expiring after 14 days.

use chrono::{DateTime, Utc};
use custodly_intake::envelope::{self, DepositFile};
use ed25519_dalek::VerifyingKey;
use x25519_dalek::StaticSecret;

fn arr32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

fn check(fixture: &str) {
    let fx: serde_json::Value = serde_json::from_str(fixture).unwrap();
    let intake = StaticSecret::from(arr32(fx["intake_secret"].as_str().unwrap()));
    let device_pub = arr32(fx["device_pub"].as_str().unwrap());
    let file: DepositFile = serde_json::from_value(fx["deposit"].clone()).unwrap();
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339(fx["created"].as_str().unwrap()).unwrap().into();

    let intake_pub = *x25519_dalek::PublicKey::from(&intake).as_bytes();
    assert_eq!(envelope::fingerprint(&intake_pub), fx["fingerprint"].as_str().unwrap());
    assert_eq!(envelope::device_code(&device_pub), fx["device_code"].as_str().unwrap());
    assert_eq!(envelope::device_id(&device_pub), file.device_id);

    let payload =
        envelope::open(&intake, &VerifyingKey::from_bytes(&device_pub).unwrap(), &file, now).unwrap();
    assert_eq!(payload.value, fx["expect_value"].as_str().unwrap());
    assert_eq!(payload.project, "custodly");
    assert_eq!(payload.name, "OPENROUTER_API_KEY");
    assert_eq!(payload.provider.as_deref(), Some("openrouter"));
}
#[test]
fn a_deposit_sealed_by_the_phone_crypto_on_a_desktop_jdk_opens_in_rust() {
    check(include_str!("fixtures/java-deposit.json"));
}

#[test]
fn a_deposit_sealed_and_signed_on_a_real_android_runtime_opens_in_rust() {
    check(include_str!("fixtures/android-deposit.json"));
}