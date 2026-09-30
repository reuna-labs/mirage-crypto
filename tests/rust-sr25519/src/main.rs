// Test-only oracle: upstream protocol, transcript, and group implementations.
use schnorrkel::{MiniSecretKey, ExpansionMode, signing_context, context::attach_rng, vrf::Malleable};
use rand_core::{RngCore, CryptoRng, Error};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT};
struct Fixed(u8);
impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 { u32::from_le_bytes([self.0;4]) }
    fn next_u64(&mut self) -> u64 { u64::from_le_bytes([self.0;8]) }
    fn fill_bytes(&mut self, out: &mut [u8]) { assert_eq!(out.len(),32); out.fill(self.0); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(),Error> { self.fill_bytes(out); Ok(()) }
}
impl CryptoRng for Fixed {}
fn main() {
    let lengths = [0,1,31,32,63,64,165,166,167,332,1024];
    for i in 0..66 {
        let seed: [u8;32] = std::array::from_fn(|j| (i*37+j*13) as u8);
        let context: Vec<u8> = (0..lengths[(i*7)%lengths.len()]).map(|j| (j*19+i) as u8).collect();
        let msg: Vec<u8> = (0..lengths[i%lengths.len()]).map(|j| (j*29+i) as u8).collect();
        let pair = MiniSecretKey::from_bytes(&seed).unwrap().expand_to_keypair(ExpansionMode::Ed25519);
        let sig = pair.sign(attach_rng(signing_context(&context).bytes(&msg), Fixed(i as u8)));
        pair.public.verify(signing_context(&context).bytes(&msg), &sig).unwrap();
        let vrf = pair.vrf_create_hash(Malleable(signing_context(b"substrate").bytes(&msg))).to_preout();
        println!("S\t{}\t{}\t{}\t{}\t{}\t{}\t{}",hex::encode(seed),hex::encode(&context),hex::encode(&msg),i,hex::encode(pair.public.to_bytes()),hex::encode(sig.to_bytes()),hex::encode(vrf.to_bytes()));
    }
    for i in 0..64 {
        let wide: [u8;64] = std::array::from_fn(|j| (i*41+j*7) as u8);
        let other: [u8;64] = std::array::from_fn(|j| (i*13+j*37) as u8);
        let a = if i == 0 { Scalar::ZERO } else { Scalar::from_bytes_mod_order_wide(&wide) };
        let b = Scalar::from_bytes_mod_order_wide(&other);
        let p = if i%16 == 0 { RistrettoPoint::default() } else { RistrettoPoint::from_uniform_bytes(&wide) };
        println!("G\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",hex::encode(wide),hex::encode(a.to_bytes()),hex::encode(b.to_bytes()),hex::encode(p.compress().to_bytes()),hex::encode((a+b).to_bytes()),hex::encode((a*b).to_bytes()),hex::encode((a*RISTRETTO_BASEPOINT_POINT).compress().to_bytes()),hex::encode((a*p).compress().to_bytes()),hex::encode(RistrettoPoint::from_uniform_bytes(&wide).compress().to_bytes()));
    }
    for i in 0..64 {
        let p: [u8;32] = match i {
            0 => [0;32],
            1 => [255;32],
            2 => { let mut b = [255;32]; b[0]=0xed; b[31]=0x7f; b },
            _ => std::array::from_fn(|j| (i*73+j*29) as u8),
        };
        println!("P\t{}\t{}",hex::encode(p),schnorrkel::PublicKey::from_bytes(&p).is_ok());
    }

}
