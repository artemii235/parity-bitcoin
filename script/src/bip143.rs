// Rust Bitcoin Library
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP143 Implementation
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use chain::{bytes::Bytes, Transaction};
use crypto::dhash256;
use primitives::hash::H256;
use script::Script;
use ser::Stream;

use std::ops::{Deref, DerefMut};

use crate::sign::{Sighash, SighashBase};
/// A replacement for SigHashComponents which supports all sighash modes
pub struct SigHashCache<R: Deref<Target = Transaction>> {
    /// Access to transaction required for various introspection
    tx: R,
    /// Hash of all the previous outputs, computed as required
    hash_prevouts: Option<H256>,
    /// Hash of all the input sequence nos, computed as required
    hash_sequence: Option<H256>,
    /// Hash of all the outputs in this transaction, computed as required
    hash_outputs: Option<H256>,
}

// fn split_anyonecanpay_flag(sighash_type: u32) -> (u32, bool) {
//     (sighash_type & 0b0111_1111, sighash_type & (1 << 7) != 0)
// }

impl<R: Deref<Target = Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        SigHashCache {
            tx,
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
        }
    }

    /// Calculate hash for prevouts
    pub fn hash_prevouts(&mut self) -> H256 {
        let hash_prevout = &mut self.hash_prevouts;
        let input = &self.tx.inputs;
        let hash = *hash_prevout
            .get_or_insert_with(|| {
                let mut enc = Stream::default();
                for txin in input {
                    enc.append(&txin.previous_output);
                }
                dhash256(&enc.out())
            })
            .clone();
        H256::from(hash)
    }

    /// Calculate hash for input sequence values
    pub fn hash_sequence(&mut self) -> H256 {
        let hash_sequence = &mut self.hash_sequence;
        let input = &self.tx.inputs;
        let hash = *hash_sequence
            .get_or_insert_with(|| {
                let mut enc = Stream::default();
                for txin in input {
                    enc.append(&txin.sequence);
                }
                dhash256(&enc.out())
            })
            .clone();
        H256::from(hash)
    }

    /// Calculate hash for outputs
    pub fn hash_outputs(&mut self) -> H256 {
        let hash_output = &mut self.hash_outputs;
        let output = &self.tx.outputs;
        let hash = *hash_output
            .get_or_insert_with(|| {
                let mut enc = Stream::default();
                for txout in output {
                    enc.append(txout);
                }
                dhash256(&enc.out())
            })
            .clone();
        H256::from(hash)
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// Stream trait.
    pub fn encode_signing_data_to(
        &mut self,
        writer: &mut Stream,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: Sighash,
    ) {
        let zero_hash = H256::default();

        // let (sighash, anyone_can_pay) = split_anyonecanpay_flag(sighash_type);

        writer.append(&self.tx.version);

        if !sighash_type.anyone_can_pay {
            let prev = &self.hash_prevouts();
            writer.append(prev);
        } else {
            writer.append(&zero_hash);
        }

        if !sighash_type.anyone_can_pay
            && sighash_type.base != SighashBase::Single
            && sighash_type.base != SighashBase::None
        {
            let sequence = &self.hash_sequence();
            writer.append(sequence);
        } else {
            writer.append(&zero_hash);
        }

        {
            let txin = &self.tx.inputs[input_index];
            writer.append(&txin.previous_output);
            writer.append_list(&**script_code);
            writer.append(&value);
            writer.append(&txin.sequence);
        }

        if sighash_type.base != SighashBase::Single && sighash_type.base != SighashBase::None {
            let outputs = &self.hash_outputs();
            writer.append(outputs);
        } else if sighash_type.base == SighashBase::Single && input_index < self.tx.outputs.len() {
            let mut single_enc = Stream::default();
            single_enc.append(&self.tx.outputs[input_index]);
            let seh = dhash256(&single_enc.out());
            writer.append(&seh);
        } else {
            writer.append(&zero_hash);
        }

        writer.append(&self.tx.lock_time);
        writer.append(&u32::from(sighash_type));
    }

    /// Compute the BIP143 sighash for any flag type. See SighashComponents::sighash_all simpler
    /// API for the most common case
    pub fn signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: Sighash,        
    ) -> H256 {
        let mut enc = Stream::default();
        self.encode_signing_data_to(&mut enc, input_index, script_code, value, sighash_type);
        let out = enc.out();
        dhash256(&out)
    }
}

impl<R: DerefMut<Target = Transaction>> SigHashCache<R> {
    /// When the SigHashCache is initialized with a mutable reference to a transaction instead of a
    /// regular reference, this method is available to allow modification to the witnesses.
    ///
    /// This allows in-line signing such as
    /// ```
    /// use bitcoin::blockdata::transaction::{Transaction, SigHashType};
    /// use bitcoin::util::bip143::SigHashCache;
    /// use bitcoin::Script;
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: 0, input: Vec::new(), output: Vec::new() };
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SigHashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::new();
    ///     let _sighash = sig_hasher.signature_hash(inp, &prevout_script, 42, SigHashType::All);
    ///     // ... sign the sighash
    ///     sig_hasher.access_witness(inp).push(Vec::new());
    /// }
    /// ```
    pub fn access_witness(&mut self, input_index: usize) -> &mut Vec<Bytes> {
        &mut self.tx.inputs[input_index].script_witness
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use chain::{hash::H264, Transaction};
    use keys::Public;
    use primitives::hash::H256;
    use script::Script;
    use sign::SignatureVersion;

    use crate::Builder;

    use super::*;

    fn chars_to_hex(hi: u8, lo: u8) -> u8 {
        let hih = (hi as char).to_digit(16).unwrap();
        let loh = (lo as char).to_digit(16).unwrap();

        let ret = (hih << 4) + loh;
        ret as u8
    }

    fn hex_to_bytes<I>(mut iter: I) -> Vec<u8>
    where
        I: Iterator<Item = u8> + ExactSizeIterator + DoubleEndedIterator,
    {
        let mut result = vec![0; iter.len() / 2];
        let mut hi = iter.next();
        let mut i = 0;
        while hi.is_some() {
            let lo = iter.next().unwrap();
            result[i] = chars_to_hex(hi.unwrap(), lo);
            hi = iter.next();
            i += 1;
        }
        result
    }

    fn p2pkh_hex(pk: &'static str) -> Script {
        let pk = H264::from(pk);
        let pk = Public::Compressed(pk);
        let witness_script = Builder::build_p2pkh(&pk.address_hash());
        witness_script
    }

    fn run_test_sighash_bip143(
        tx: &'static str,
        script: &'static str,
        input_index: usize,
        value: u64,
        hash_type: u32,
        expected_result: &'static str,
    ) {
        let tx: Transaction = tx.into();
        let script = Script::from(script);
        let raw_expected = hex_to_bytes(expected_result.bytes());
        let raw_expected: Vec<u8> = raw_expected.into_iter().rev().collect();
        let expected_result = H256::from(&raw_expected[..]);
        let mut cache = SigHashCache::new(&tx);
        let sighash_type = Sighash::from_u32(SignatureVersion::WitnessV0, hash_type);
        let actual_result = cache.signature_hash(input_index, &script, value, sighash_type);
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn bip143_p2wpkh() {
        let raw_tx: &'static str =
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
        0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
        00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093\
        510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
        let tx: Transaction = raw_tx.into();
        let witness_script =
            p2pkh_hex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
        let value = 600_000_000;

        let mut comp = SigHashCache::new(&tx);
        let hash_prevouts =
            H256::from("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37");
        let hash_sequence =
            H256::from("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b");
        let hash_outputs =
            H256::from("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5");
        let actual_hash_prevouts = comp.hash_prevouts();
        println!("actual_hash_prevouts \t {}", actual_hash_prevouts);
        let actual_hash_sequence = comp.hash_sequence();
        println!("actual_hash_sequence \t {}", actual_hash_sequence);
        let actual_hash_outputs = comp.hash_outputs();
        println!("actual_hash_outputs \t {}", actual_hash_outputs);
        assert_eq!(actual_hash_prevouts, hash_prevouts);
        assert_eq!(actual_hash_sequence, hash_sequence);
        assert_eq!(actual_hash_outputs, hash_outputs);

        let actual_hash = comp.signature_hash(
            1,
            &witness_script,
            value,
            Sighash::from_u32(SignatureVersion::WitnessV0, 1),
        );
        let expected_hash =
            H256::from("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn bip143_p2wpkh_nested_in_p2sh() {
        let raw_tx: &'static str =
            "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000\
            0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac00\
            08af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000";
        let tx: Transaction = raw_tx.into();

        let witness_script =
            p2pkh_hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        let value = 1_000_000_000;

        let mut comp = SigHashCache::new(&tx);
        let hash_prevouts =
            H256::from("b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a");
        let hash_sequence =
            H256::from("18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198");
        let hash_outputs =
            H256::from("de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83");
        assert_eq!(comp.hash_prevouts(), hash_prevouts);
        assert_eq!(comp.hash_sequence(), hash_sequence);
        assert_eq!(comp.hash_outputs(), hash_outputs);

        let actual_hash = comp.signature_hash(
            0,
            &witness_script,
            value,
            Sighash::from_u32(SignatureVersion::WitnessV0, 1),
        );
        let expected_hash =
            H256::from("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6");
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn bip143_p2wsh_nested_in_p2sh() {
        let raw_tx: &'static str =
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000\
        ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f\
        05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
        let tx: Transaction = raw_tx.into();

        let witness_script = Script::from(
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28\
             bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
             9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58\
             c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b1486\
             2c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
             56ae",
        );
        let value = 987654321;

        let mut comp = SigHashCache::new(&tx);
        let hash_prevouts =
            H256::from("74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0");
        let hash_sequence =
            H256::from("3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044");
        let hash_outputs =
            H256::from("bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc");
        assert_eq!(comp.hash_prevouts(), hash_prevouts);
        assert_eq!(comp.hash_sequence(), hash_sequence);
        assert_eq!(comp.hash_outputs(), hash_outputs);

        let actual_hash = comp.signature_hash(
            0,
            &witness_script,
            value,
            Sighash::from_u32(SignatureVersion::WitnessV0, 1),
        );
        let expected_hash =
            H256::from("185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c");
        assert_eq!(actual_hash, expected_hash);
    }
    #[test]
    fn bip143_sighash_flags() {
        // All examples generated via Bitcoin Core RPC using signrawtransactionwithwallet
        // with additional debug printing

        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x01, "0a1bc2758dbb5b3a56646f8cafbf63f410cc62b77a482f8b87552683300a7711");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x02, "3e275ac8b084f79f756dcd535bffb615cc94a685eefa244d9031eaf22e4cec12");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x03, "191a08165ffacc3ea55753b225f323c35fd00d9cc0268081a4a501921fc6ec14");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x81, "4b6b612530f94470bbbdef18f57f2990d56b239f41b8728b9a49dc8121de4559");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x82, "a7e916d3acd4bb97a21e6793828279aeab02162adf8099ea4f309af81f3d5adb");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x83, "d9276e2a48648ddb53a4aaa58314fc2b8067c13013e1913ffb67e0988ce82c78");
    }
}
