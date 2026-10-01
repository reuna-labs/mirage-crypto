use ed25519_bip32::{XPrv, DerivationScheme};
fn hex(b: &[u8]) -> String { b.iter().map(|x|format!("{x:02x}")).collect() }
fn main() {
    println!("# Rust ed25519-bip32 2066bbfa011d26a5ea18cf4558240e9299bd0668");
    for n in 0..32 {
        let raw = std::array::from_fn(|i| (i*13+n*37) as u8);
        let root = XPrv::normalize_bytes_force3rd(raw);
        for path in [vec![],vec![0,1,0x7fffffff],vec![0x80000000,0xffffffff,17],vec![1852|0x80000000,1815|0x80000000,0x80000000,0,7]] {
            let mut key = root.clone();
            for &i in &path { key = key.derive(DerivationScheme::V2,i); }
            let msg: Vec<u8> = (0..[0,1,127,128,129,255,1024,8193][n%8]).map(|i| (i+n) as u8).collect();
            let sig = key.sign::<()>(&msg);
            println!("{}\t{}\t{}\t{}\t{}\t{}",hex(root.as_ref()),path.iter().map(|i|format!("{i}")).collect::<Vec<_>>().join(","),hex(key.as_ref()),hex(key.public().as_ref()),hex(&msg),hex(sig.as_ref()));
        }
    }
}
