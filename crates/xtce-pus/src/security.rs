//! `#![no_std]` telecommand authentication and anti-replay protection for dual-use missions.
//!
//! Modern European and Polish dual-use constellations (such as *PIAST* and *CAMILA*) require
//! uplink authentication and replay resistance to prevent unauthorized command injection or
//! capture-and-replay attacks over RF links.
//!
//! This module implements a zero-allocation, constant-time 64-bit Keyed Message Authentication
//! Code (SipHash-2-4, RFC 10130 / Aumasson & Bernstein) coupled with a strictly monotonic
//! 32-bit anti-replay counter (`TcSecurityGate`).

/// Length of the 128-bit pre-shared spacecraft uplink authentication key in octets.
pub const AUTH_KEY_LEN: usize = 16;

/// Length of the appended telecommand security trailer (`4-byte counter || 8-byte MAC tag`).
pub const TC_AUTH_TRAILER_LEN: usize = 12;

/// Failure code reported when a telecommand carries an expired or replayed counter.
pub const ERR_CODE_REPLAY_DETECTED: u16 = 0x5EC1;

/// Failure code reported when a telecommand's 64-bit authentication tag is invalid.
pub const ERR_CODE_AUTH_FAILED: u16 = 0x5EC2;

/// Errors returned by [`TcSecurityGate`] when verifying an authenticated telecommand.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityError {
    /// The application data is too short to contain the 12-byte authentication trailer.
    MissingTrailer,
    /// The 32-bit counter is less than or equal to the last accepted telecommand counter.
    ReplayAttack {
        /// Counter value received in the telecommand trailer.
        received: u32,
        /// Highest counter value previously accepted by the spacecraft.
        last_accepted: u32,
    },
    /// Constant-time MAC verification failed (invalid key or tampered payload).
    InvalidMacTag,
}

/// Computes a 64-bit SipHash-2-4 authentication tag over `counter` and `data` using `key`.
#[must_use]
pub const fn compute_mac_tag(key: &[u8; AUTH_KEY_LEN], counter: u32, data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    // Mix the 32-bit monotonic anti-replay counter as the first 64-bit domain word
    let counter_word = (counter as u64) | 0xA5A5_0000_0000_0000;
    v3 ^= counter_word;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= counter_word;

    let len = data.len();
    let full_chunks = len / 8;
    let mut i = 0usize;
    while i < full_chunks {
        let base = i * 8;
        let m = u64::from_le_bytes([
            data[base],
            data[base + 1],
            data[base + 2],
            data[base + 3],
            data[base + 4],
            data[base + 5],
            data[base + 6],
            data[base + 7],
        ]);
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 1;
    }

    let mut tail = ((len & 0xFF) as u64) << 56;
    let rem_start = full_chunks * 8;
    let mut r = 0usize;
    while rem_start + r < len {
        tail |= (data[rem_start + r] as u64) << (r * 8);
        r += 1;
    }

    v3 ^= tail;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= tail;

    v2 ^= 0xFF;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

const fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Encodes a 12-byte authentication trailer (`4-byte big-endian counter || 8-byte big-endian MAC`).
#[must_use]
pub const fn build_auth_trailer(
    key: &[u8; AUTH_KEY_LEN],
    counter: u32,
    app_data: &[u8],
) -> [u8; TC_AUTH_TRAILER_LEN] {
    let tag = compute_mac_tag(key, counter, app_data);
    let c = counter.to_be_bytes();
    let t = tag.to_be_bytes();
    [
        c[0], c[1], c[2], c[3], t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
    ]
}

/// On-board telecommand security gate enforcing anti-replay and MAC verification.
#[derive(Clone, Debug)]
pub struct TcSecurityGate {
    key: [u8; AUTH_KEY_LEN],
    last_counter: u32,
}

impl TcSecurityGate {
    /// Creates a new security gate with a 128-bit pre-shared uplink key and initial counter `0`.
    #[must_use]
    pub const fn new(key: [u8; AUTH_KEY_LEN]) -> Self {
        Self {
            key,
            last_counter: 0,
        }
    }

    /// The highest anti-replay counter accepted so far.
    #[must_use]
    pub const fn last_counter(&self) -> u32 {
        self.last_counter
    }

    /// Verifies `signed_app_data` (`payload || 12-byte trailer`), returning the authenticated
    /// payload slice and advancing the anti-replay watermark on success.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError`] if the trailer is missing, the counter is replayed, or the
    /// 64-bit MAC tag does not match in constant time.
    pub fn verify_and_strip<'a>(
        &mut self,
        signed_app_data: &'a [u8],
    ) -> Result<&'a [u8], SecurityError> {
        if signed_app_data.len() < TC_AUTH_TRAILER_LEN {
            return Err(SecurityError::MissingTrailer);
        }
        let split = signed_app_data.len() - TC_AUTH_TRAILER_LEN;
        let payload = &signed_app_data[..split];
        let trailer = &signed_app_data[split..];

        let counter = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        if counter <= self.last_counter {
            return Err(SecurityError::ReplayAttack {
                received: counter,
                last_accepted: self.last_counter,
            });
        }

        let expected_tag = compute_mac_tag(&self.key, counter, payload).to_be_bytes();
        let mut diff = 0u8;
        let mut i = 0usize;
        while i < 8 {
            diff |= trailer[4 + i] ^ expected_tag[i];
            i += 1;
        }

        if diff != 0 {
            return Err(SecurityError::InvalidMacTag);
        }

        self.last_counter = counter;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::{AUTH_KEY_LEN, SecurityError, TcSecurityGate, build_auth_trailer};

    const TEST_KEY: [u8; AUTH_KEY_LEN] = *b"POLSA_CAMILA_KEY";

    #[test]
    fn accepts_authentic_monotonic_commands_and_rejects_replay_or_tampering() {
        let mut gate = TcSecurityGate::new(TEST_KEY);
        let payload = [0x00, 0x10]; // Function_ID = 0x0010
        let trailer = build_auth_trailer(&TEST_KEY, 1, &payload);

        let mut signed = [0u8; 14];
        signed[..2].copy_from_slice(&payload);
        signed[2..].copy_from_slice(&trailer);

        let verified = gate.verify_and_strip(&signed).expect("first TC valid");
        assert_eq!(verified, &payload);
        assert_eq!(gate.last_counter(), 1);

        // Replaying the exact same frame must be rejected
        assert_eq!(
            gate.verify_and_strip(&signed),
            Err(SecurityError::ReplayAttack {
                received: 1,
                last_accepted: 1,
            })
        );

        // Counter = 2 with tampered payload byte must be rejected
        let trailer2 = build_auth_trailer(&TEST_KEY, 2, &payload);
        signed[2..].copy_from_slice(&trailer2);
        signed[1] ^= 0x01;
        assert_eq!(
            gate.verify_and_strip(&signed),
            Err(SecurityError::InvalidMacTag)
        );
    }
}
