use hex::FromHex;
use compact::Compact;
use crypto::dhash256;
use hash::{EquihashSolution, H256};
use ser::{deserialize, serialize, CompactInteger, Deserializable, Reader, Serializable, Stream};
use std::{fmt, io};
use Transaction;
use transaction::{deserialize_tx, TxType};

#[derive(Clone, Debug, PartialEq)]
pub enum BlockHeaderNonce {
	U32(u32),
	H256(H256)
}

impl Serializable for BlockHeaderNonce {
	fn serialize(&self, s: &mut Stream) {
		match self {
			BlockHeaderNonce::U32(n) => s.append(n),
			BlockHeaderNonce::H256(h) => s.append(h),
		};
	}
}

#[derive(Clone, Debug, PartialEq)]
pub enum BlockHeaderBits {
	Compact(Compact),
	U32(u32),
}

impl Serializable for BlockHeaderBits {
	fn serialize(&self, s: &mut Stream) {
		match self {
			BlockHeaderBits::Compact(c) => s.append(c),
			BlockHeaderBits::U32(n) => s.append(n),
		};
	}
}

const AUX_POW_VERSION: u32 = 6422788;

#[derive(Clone, Debug, PartialEq, Deserializable, Serializable)]
pub struct MerkleBranch {
	branch_hashes: Vec<H256>,
	branch_side_mask: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuxPow {
	coinbase_tx: Transaction,
	parent_block_hash: H256,
	coinbase_branch: MerkleBranch,
	blockchain_branch: MerkleBranch,
	parent_block_header: Box<BlockHeader>,
}

impl Serializable for AuxPow {
	fn serialize(&self, s: &mut Stream) {
		s.append(&self.coinbase_tx);
		s.append(&self.parent_block_hash);
		s.append(&self.coinbase_branch);
		s.append(&self.blockchain_branch);
		s.append(self.parent_block_header.as_ref());
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlockHeader {
	pub version: u32,
	pub previous_header_hash: H256,
	pub merkle_root_hash: H256,
	pub hash_final_sapling_root: Option<H256>,
	pub time: u32,
	pub bits: BlockHeaderBits,
	pub nonce: BlockHeaderNonce,
	pub solution_size: Option<CompactInteger>,
	pub solution: Option<EquihashSolution>,
	pub aux_pow: Option<AuxPow>,
}

impl Serializable for BlockHeader {
	fn serialize(&self, s: &mut Stream) {
		s.append(&self.version);
		s.append(&self.previous_header_hash);
		s.append(&self.merkle_root_hash);
		match &self.hash_final_sapling_root {
			Some(h) => { s.append(h); },
			None => (),
		};
		s.append(&self.time);
		s.append(&self.bits);
		s.append(&self.nonce);
		match &self.solution_size {
			Some(size) => { s.append(size); },
			None => (),
		};
		match &self.solution {
			Some(sol) => { s.append(sol); },
			None => (),
		};
		match &self.aux_pow {
			Some(pow) => { s.append(pow); },
			None => (),
		};
	}
}

impl Deserializable for BlockHeader {
	fn deserialize<T: io::Read>(reader: &mut Reader<T>) -> Result<Self, ser::Error> where Self: Sized {
		let version = reader.read()?;
		let previous_header_hash = reader.read()?;
		let merkle_root_hash = reader.read()?;
		let hash_final_sapling_root = if version == 4 {
			Some(reader.read()?)
		} else {
			None
		};
		let time = reader.read()?;
		let bits = if version == 4 {
			BlockHeaderBits::U32(reader.read()?)
		} else {
			BlockHeaderBits::Compact(reader.read()?)
		};
		let nonce = if version == 4 {
			BlockHeaderNonce::H256(reader.read()?)
		} else {
			BlockHeaderNonce::U32(reader.read()?)
		};
		let solution_size = if version == 4 {
			Some(reader.read()?)
		} else {
			None
		};
		let solution = if version == 4 {
			Some(reader.read()?)
		} else {
			None
		};

		// https://en.bitcoin.it/wiki/Merged_mining_specification#Merged_mining_coinbase
		let aux_pow = if version == AUX_POW_VERSION {
			let coinbase_tx = deserialize_tx(reader, TxType::StandardWithWitness)?;
			let parent_block_hash = reader.read()?;
			let coinbase_branch = reader.read()?;
			let blockchain_branch = reader.read()?;
			let parent_block_header = Box::new(reader.read()?);
			Some(AuxPow {
				coinbase_tx,
				parent_block_hash,
				coinbase_branch,
				blockchain_branch,
				parent_block_header,
			})
		} else {
			None
		};

		Ok(BlockHeader {
			version,
			previous_header_hash,
			merkle_root_hash,
			hash_final_sapling_root,
			time,
			bits,
			nonce,
			solution_size,
			solution,
			aux_pow,
		})
	}
}

impl BlockHeader {
	pub fn hash(&self) -> H256 {
		dhash256(&serialize(self))
	}
}

impl From<&'static str> for BlockHeader {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
	}
}

#[cfg(test)]
mod tests {
	use hex::FromHex;
	use ser::{deserialize, serialize, serialize_list, Error as ReaderError, Reader, Stream};
	use super::BlockHeader;
	use block_header::{BlockHeaderBits, BlockHeaderNonce, AUX_POW_VERSION};

	#[test]
	fn test_block_header_stream() {
		let block_header = BlockHeader {
			version: 1,
			previous_header_hash: [2; 32].into(),
			merkle_root_hash: [3; 32].into(),
			hash_final_sapling_root: None,
			time: 4,
			bits: BlockHeaderBits::Compact(5.into()),
			nonce: BlockHeaderNonce::U32(6),
			solution: None,
			solution_size: None,
			aux_pow: None,
		};

		let mut stream = Stream::default();
		stream.append(&block_header);

		let expected = vec![
			1, 0, 0, 0,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
			4, 0, 0, 0,
			5, 0, 0, 0,
			6, 0, 0, 0,
		].into();

		assert_eq!(stream.out(), expected);
	}

	#[test]
	fn test_block_header_reader() {
		let buffer = vec![
			1, 0, 0, 0,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
			4, 0, 0, 0,
			5, 0, 0, 0,
			6, 0, 0, 0,
		];

		let mut reader = Reader::new(&buffer);

		let expected = BlockHeader {
			version: 1,
			previous_header_hash: [2; 32].into(),
			merkle_root_hash: [3; 32].into(),
			hash_final_sapling_root: Default::default(),
			time: 4,
			bits: BlockHeaderBits::Compact(5.into()),
			nonce: BlockHeaderNonce::U32(6),
			solution_size: None,
			solution: None,
			aux_pow: None,
		};

		assert_eq!(expected, reader.read().unwrap());
		assert_eq!(ReaderError::UnexpectedEnd, reader.read::<BlockHeader>().unwrap_err());
	}

	#[test]
	fn test_sapling_block_header_serde() {
		// block header of https://kmdexplorer.io/block/01ad31e22fea912a974c3e1eea11dc26348676528a586f77199ac3cfe29e271f
		let header_hex = "040000008e4e7283b71dd1572d220935db0a1654d1042e92378579f8abab67b143f93a02fa026610d2634b72ff729b9ea7850c0d2c25eeaf7a82878ca42a8e9912028863a2d8a734eb73a4dc734072dbfd12406f1e7121bfe0e3d6c10922495c44e5cc1c91185d5ee519011d0400b9caaf41d4b63a6ab55bb4e6925d46fc3adea7be37b713d3a615e7cf0000fd40050001a80fa65b9a46fdb1506a7a4d26f43e7995d69902489b9f6c4599c88f9c169605cc135258953da0d6299ada4ff81a76ad63c943261078d5dd1918f91cea68b65b7fc362e9df49ba57c2ea5c6dba91591c85eb0d59a1905ac66e2295b7a291a1695301489a3cc7310fd45f2b94e3b8d94f3051e9bbaada1e0641fcec6e0d6230e76753aa9574a3f3e28eaa085959beffd3231dbe1aeea3955328f3a973650a38e31632a4ffc7ec007a3345124c0b99114e2444b3ef0ada75adbd077b247bbf3229adcffbe95bc62daac88f96317d5768540b5db636f8c39a8529a736465ed830ab2c1bbddf523587abe14397a6f1835d248092c4b5b691a955572607093177a5911e317739187b41f4aa662aa6bca0401f1a0a77915ebb6947db686cff549c5f4e7b9dd93123b00a1ae8d411cfb13fa7674de21cbee8e9fc74e12aa6753b261eab3d9256c7c32cc9b16219dad73c61014e7d88d74d5e218f12e11bc47557347ff49a9ab4490647418d2a5c2da1df24d16dfb611173608fe4b10a357b0fa7a1918b9f2d7836c84bf05f384e1e678b2fdd47af0d8e66e739fe45209ede151a180aba1188058a0db093e30bc9851980cf6fbfa5adb612d1146905da662c3347d7e7e569a1041641049d951ab867bc0c6a3863c7667d43f596a849434958cee2b63dc8fa11bd0f38aa96df86ed66461993f64736345313053508c4e939506c08a766f5b6ed0950759f3901bbc4db3dc97e05bf20b9dda4ff242083db304a4e487ac2101b823998371542354e5d534b5b6ae6420cc19b11512108b61208f4d9a5a97263d2c060da893544dea6251bcadc682d2238af35f2b1c2f65a73b89a4e194f9e1eef6f0e5948ef8d0d2862f48fd3356126b00c6a2d3770ecd0d1a78fa34974b454f270b23d461e357c9356c19496522b59ff9d5b4608c542ff89e558798324021704b2cfe9f6c1a70906c43c7a690f16615f198d29fa647d84ce8461fa570b33e3eada2ed7d77e1f280a0d2e9f03c2e1db535d922b1759a191b417595f3c15d8e8b7f810527ff942e18443a3860e67ccba356809ecedc31c5d8db59c7e039dae4b53d126679e8ffa20cc26e8b9d229c8f6ee434ad053f5f4f5a94e249a13afb995aad82b4d90890187e516e114b168fc7c7e291b9738ea578a7bab0ba31030b14ba90b772b577806ea2d17856b0cb9e74254ba582a9f2638ea7ed2ca23be898c6108ff8f466b443537ed9ec56b8771bfbf0f2f6e1092a28a7fd182f111e1dbdd155ea82c6cb72d5f9e6518cc667b8226b5f5c6646125fc851e97cf125f48949f988ed37c4283072fc03dd1da3e35161e17f44c0e22c76f708bb66405737ef24176e291b4fc2eadab876115dc62d48e053a85f0ad132ef07ad5175b036fe39e1ad14fcdcdc6ac5b3daabe05161a72a50545dd812e0f9af133d061b726f491e904d89ee57811ef58d3bda151f577aed381963a30d91fb98dc49413300d132a7021a5e834e266b4ac982d76e00f43f5336b8e8028a0cacfa11813b01e50f71236a73a4c0d0757c1832b0680ada56c80edf070f438ab2bc587542f926ff8d3644b8b8a56c78576f127dec7aed9cb3e1bc2442f978a9df1dc3056a63e653132d0f419213d3cb86e7b61720de1aa3af4b3757a58156970da27560c6629257158452b9d5e4283dc6fe7df42d2fda3352d5b62ce5a984d912777c3b01837df8968a4d494db1b663e0e68197dbf196f21ea11a77095263dec548e2010460840231329d83978885ee2423e8b327785970e27c6c6d436157fb5b56119b19239edbb730ebae013d82c35df4a6e70818a74d1ef7a2e87c090ff90e32939f58ed24e85b492b5750fd2cd14b9b8517136b76b1cc6ccc6f6f027f65f1967a0eb4f32cd6e5d5315";
		let header_bytes: Vec<u8> = header_hex.from_hex().unwrap();
		let header: BlockHeader = deserialize(header_bytes.as_slice()).unwrap();
		let expected_header = BlockHeader { version: 4, previous_header_hash: "8e4e7283b71dd1572d220935db0a1654d1042e92378579f8abab67b143f93a02".into(), merkle_root_hash: "fa026610d2634b72ff729b9ea7850c0d2c25eeaf7a82878ca42a8e9912028863".into(), hash_final_sapling_root: Some("a2d8a734eb73a4dc734072dbfd12406f1e7121bfe0e3d6c10922495c44e5cc1c".into()), time: 1583159441, bits: BlockHeaderBits::U32(486611429), nonce: BlockHeaderNonce::H256("0400b9caaf41d4b63a6ab55bb4e6925d46fc3adea7be37b713d3a615e7cf0000".into()), solution_size: Some(1344u32.into()), solution: Some("0001a80fa65b9a46fdb1506a7a4d26f43e7995d69902489b9f6c4599c88f9c169605cc135258953da0d6299ada4ff81a76ad63c943261078d5dd1918f91cea68b65b7fc362e9df49ba57c2ea5c6dba91591c85eb0d59a1905ac66e2295b7a291a1695301489a3cc7310fd45f2b94e3b8d94f3051e9bbaada1e0641fcec6e0d6230e76753aa9574a3f3e28eaa085959beffd3231dbe1aeea3955328f3a973650a38e31632a4ffc7ec007a3345124c0b99114e2444b3ef0ada75adbd077b247bbf3229adcffbe95bc62daac88f96317d5768540b5db636f8c39a8529a736465ed830ab2c1bbddf523587abe14397a6f1835d248092c4b5b691a955572607093177a5911e317739187b41f4aa662aa6bca0401f1a0a77915ebb6947db686cff549c5f4e7b9dd93123b00a1ae8d411cfb13fa7674de21cbee8e9fc74e12aa6753b261eab3d9256c7c32cc9b16219dad73c61014e7d88d74d5e218f12e11bc47557347ff49a9ab4490647418d2a5c2da1df24d16dfb611173608fe4b10a357b0fa7a1918b9f2d7836c84bf05f384e1e678b2fdd47af0d8e66e739fe45209ede151a180aba1188058a0db093e30bc9851980cf6fbfa5adb612d1146905da662c3347d7e7e569a1041641049d951ab867bc0c6a3863c7667d43f596a849434958cee2b63dc8fa11bd0f38aa96df86ed66461993f64736345313053508c4e939506c08a766f5b6ed0950759f3901bbc4db3dc97e05bf20b9dda4ff242083db304a4e487ac2101b823998371542354e5d534b5b6ae6420cc19b11512108b61208f4d9a5a97263d2c060da893544dea6251bcadc682d2238af35f2b1c2f65a73b89a4e194f9e1eef6f0e5948ef8d0d2862f48fd3356126b00c6a2d3770ecd0d1a78fa34974b454f270b23d461e357c9356c19496522b59ff9d5b4608c542ff89e558798324021704b2cfe9f6c1a70906c43c7a690f16615f198d29fa647d84ce8461fa570b33e3eada2ed7d77e1f280a0d2e9f03c2e1db535d922b1759a191b417595f3c15d8e8b7f810527ff942e18443a3860e67ccba356809ecedc31c5d8db59c7e039dae4b53d126679e8ffa20cc26e8b9d229c8f6ee434ad053f5f4f5a94e249a13afb995aad82b4d90890187e516e114b168fc7c7e291b9738ea578a7bab0ba31030b14ba90b772b577806ea2d17856b0cb9e74254ba582a9f2638ea7ed2ca23be898c6108ff8f466b443537ed9ec56b8771bfbf0f2f6e1092a28a7fd182f111e1dbdd155ea82c6cb72d5f9e6518cc667b8226b5f5c6646125fc851e97cf125f48949f988ed37c4283072fc03dd1da3e35161e17f44c0e22c76f708bb66405737ef24176e291b4fc2eadab876115dc62d48e053a85f0ad132ef07ad5175b036fe39e1ad14fcdcdc6ac5b3daabe05161a72a50545dd812e0f9af133d061b726f491e904d89ee57811ef58d3bda151f577aed381963a30d91fb98dc49413300d132a7021a5e834e266b4ac982d76e00f43f5336b8e8028a0cacfa11813b01e50f71236a73a4c0d0757c1832b0680ada56c80edf070f438ab2bc587542f926ff8d3644b8b8a56c78576f127dec7aed9cb3e1bc2442f978a9df1dc3056a63e653132d0f419213d3cb86e7b61720de1aa3af4b3757a58156970da27560c6629257158452b9d5e4283dc6fe7df42d2fda3352d5b62ce5a984d912777c3b01837df8968a4d494db1b663e0e68197dbf196f21ea11a77095263dec548e2010460840231329d83978885ee2423e8b327785970e27c6c6d436157fb5b56119b19239edbb730ebae013d82c35df4a6e70818a74d1ef7a2e87c090ff90e32939f58ed24e85b492b5750fd2cd14b9b8517136b76b1cc6ccc6f6f027f65f1967a0eb4f32cd6e5d5315".into()), aux_pow: None, };
		assert_eq!(expected_header, header);
		let serialized = serialize(&header);
		assert_eq!(serialized.take(), header_bytes);
	}

	#[test]
	fn test_doge_block_headers_serde() {
		// block headers of https://dogechain.info/block/3631810 and https://dogechain.info/block/3631811
		let headers_bytes: &[u8] = &[02, 4, 1, 98, 0, 169, 253, 69, 196, 153, 115, 241, 239, 162, 112, 182, 254, 4, 175, 104, 238, 165, 178, 80, 67, 77, 109, 241, 134, 124, 3, 242, 203, 235, 211, 98, 185, 102, 124, 144, 105, 144, 228, 58, 25, 26, 29, 216, 102, 231, 53, 25, 58, 159, 46, 197, 119, 233, 12, 222, 197, 160, 216, 46, 103, 50, 8, 32, 168, 206, 162, 64, 96, 194, 112, 3, 26, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 85, 3, 44, 175, 30, 65, 216, 16, 40, 191, 172, 120, 159, 65, 216, 16, 40, 191, 75, 114, 51, 47, 76, 84, 67, 46, 84, 79, 80, 47, 250, 190, 109, 109, 43, 81, 248, 197, 12, 188, 108, 251, 133, 201, 23, 87, 181, 238, 195, 234, 79, 166, 231, 37, 167, 174, 120, 157, 213, 105, 44, 122, 118, 203, 54, 251, 1, 0, 0, 0, 0, 0, 0, 0, 155, 13, 193, 150, 4, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 2, 189, 135, 129, 74, 0, 0, 0, 0, 25, 118, 169, 20, 12, 97, 127, 219, 46, 164, 42, 237, 48, 165, 9, 89, 94, 226, 27, 163, 246, 104, 141, 176, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 189, 110, 250, 90, 149, 67, 81, 162, 34, 33, 76, 16, 172, 85, 135, 43, 220, 178, 255, 87, 123, 75, 46, 134, 48, 209, 202, 92, 79, 18, 11, 164, 0, 0, 0, 0, 215, 213, 182, 131, 194, 95, 244, 213, 149, 120, 21, 208, 183, 72, 141, 171, 212, 164, 167, 119, 251, 21, 37, 177, 229, 184, 97, 162, 24, 119, 242, 161, 4, 209, 134, 48, 129, 122, 174, 143, 140, 6, 234, 87, 92, 113, 77, 128, 196, 62, 199, 14, 21, 210, 137, 140, 250, 158, 150, 215, 86, 67, 93, 91, 139, 0, 245, 112, 111, 136, 183, 150, 231, 215, 166, 109, 16, 186, 116, 56, 110, 194, 165, 34, 90, 99, 84, 66, 184, 117, 82, 7, 219, 250, 77, 91, 51, 209, 43, 142, 88, 192, 2, 229, 82, 194, 220, 219, 237, 19, 233, 162, 174, 32, 217, 118, 222, 150, 192, 215, 97, 141, 172, 255, 3, 235, 10, 56, 221, 210, 25, 28, 187, 23, 252, 102, 236, 147, 174, 64, 20, 78, 177, 193, 179, 152, 118, 74, 96, 166, 100, 24, 97, 159, 51, 154, 71, 207, 194, 165, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 31, 50, 15, 173, 125, 76, 148, 26, 189, 206, 165, 146, 170, 134, 156, 146, 171, 130, 145, 255, 94, 39, 213, 55, 204, 174, 206, 38, 32, 121, 53, 132, 76, 220, 7, 99, 160, 170, 90, 57, 46, 105, 165, 61, 210, 58, 159, 187, 210, 33, 167, 58, 217, 231, 58, 121, 219, 26, 28, 79, 51, 73, 198, 161, 253, 162, 64, 96, 56, 160, 1, 26, 179, 6, 202, 226, 4, 1, 98, 0, 251, 54, 203, 118, 122, 44, 105, 213, 157, 120, 174, 167, 37, 231, 166, 79, 234, 195, 238, 181, 87, 23, 201, 133, 251, 108, 188, 12, 197, 248, 81, 43, 135, 148, 130, 18, 84, 184, 105, 138, 17, 165, 157, 180, 227, 34, 105, 187, 76, 248, 74, 60, 56, 75, 253, 10, 39, 3, 210, 17, 35, 239, 79, 73, 100, 163, 64, 96, 73, 207, 2, 26, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 93, 3, 45, 175, 30, 26, 47, 86, 105, 97, 66, 84, 67, 47, 77, 105, 110, 101, 100, 32, 98, 121, 32, 106, 101, 102, 102, 56, 56, 56, 56, 47, 44, 250, 190, 109, 109, 97, 206, 202, 198, 28, 194, 8, 255, 246, 174, 74, 110, 232, 94, 195, 183, 51, 148, 238, 56, 158, 70, 208, 240, 182, 52, 132, 156, 133, 82, 177, 163, 16, 0, 0, 0, 0, 0, 0, 0, 16, 252, 249, 144, 1, 88, 220, 181, 179, 211, 187, 198, 156, 2, 0, 0, 0, 255, 255, 255, 255, 2, 15, 158, 162, 74, 0, 0, 0, 0, 25, 118, 169, 20, 225, 108, 40, 20, 110, 212, 134, 156, 25, 11, 63, 11, 220, 24, 216, 13, 69, 249, 33, 52, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 2, 66, 232, 219, 204, 165, 29, 255, 185, 205, 155, 16, 117, 64, 45, 24, 80, 20, 179, 238, 117, 246, 211, 22, 9, 119, 54, 211, 20, 85, 74, 6, 0, 0, 0, 0, 43, 57, 188, 104, 36, 21, 183, 215, 42, 5, 102, 127, 202, 214, 108, 27, 197, 78, 223, 117, 192, 184, 134, 95, 200, 0, 82, 210, 90, 48, 120, 31, 7, 109, 146, 28, 130, 42, 82, 151, 152, 163, 13, 231, 93, 146, 206, 199, 97, 18, 81, 19, 20, 6, 180, 179, 243, 8, 66, 160, 156, 116, 142, 49, 129, 159, 248, 160, 150, 185, 241, 19, 67, 139, 52, 214, 253, 19, 72, 94, 83, 47, 211, 73, 60, 64, 51, 17, 205, 49, 64, 60, 101, 96, 141, 43, 55, 180, 136, 70, 78, 130, 81, 124, 47, 252, 28, 10, 240, 32, 175, 114, 198, 188, 17, 161, 166, 212, 248, 96, 171, 190, 173, 10, 150, 239, 161, 243, 217, 9, 169, 105, 92, 111, 42, 195, 51, 5, 245, 171, 165, 29, 74, 61, 62, 150, 221, 185, 137, 79, 121, 37, 17, 168, 208, 58, 59, 235, 188, 196, 123, 110, 112, 16, 207, 56, 189, 15, 210, 113, 249, 225, 1, 34, 91, 139, 248, 187, 81, 47, 11, 33, 234, 33, 211, 194, 103, 248, 88, 69, 209, 229, 119, 113, 197, 177, 190, 178, 170, 56, 78, 205, 245, 238, 241, 101, 115, 157, 54, 41, 150, 78, 7, 122, 171, 19, 81, 82, 24, 164, 131, 138, 72, 2, 234, 244, 240, 15, 193, 148, 82, 85, 95, 75, 216, 23, 62, 158, 77, 240, 54, 9, 168, 136, 95, 38, 217, 48, 133, 43, 45, 71, 124, 138, 211, 25, 134, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 226, 246, 28, 63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249, 130, 61, 12, 168, 187, 14, 212, 164, 65, 32, 137, 209, 167, 140, 244, 182, 71, 110, 180, 21, 135, 85, 93, 252, 166, 190, 24, 216, 150, 239, 125, 52, 148, 133, 125, 62, 8, 145, 143, 112, 57, 93, 146, 6, 65, 15, 191, 169, 66, 241, 168, 137, 170, 90, 184, 24, 142, 195, 60, 47, 110, 32, 125, 199, 8, 0, 0, 0, 0, 0, 0, 32, 215, 213, 182, 131, 194, 95, 244, 213, 149, 120, 21, 208, 183, 72, 141, 171, 212, 164, 167, 119, 251, 21, 37, 177, 229, 184, 97, 162, 24, 119, 242, 161, 248, 83, 77, 1, 16, 248, 195, 108, 190, 102, 184, 134, 65, 164, 171, 176, 181, 203, 34, 69, 74, 19, 48, 160, 149, 131, 65, 190, 33, 165, 67, 202, 136, 163, 64, 96, 56, 160, 1, 26, 204, 233, 213, 44];
		let mut reader = Reader::new(headers_bytes);
		let headers = reader.read_list::<BlockHeader>().unwrap();
		assert_eq!(headers[0].version, AUX_POW_VERSION);
		assert_eq!(headers[1].version, AUX_POW_VERSION);
		let serialized = serialize_list(&headers);
		assert_eq!(serialized.take(), headers_bytes);
	}
}
