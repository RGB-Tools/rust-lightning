//! A module to provide RGB functionality

use lightning::ln::PaymentHash;
use lightning::ln::channelmanager::ChannelDetails;
use lightning::rgb_utils::{RgbInfo, RgbPaymentInfo};

use rgb::ContractId;

#[cfg(feature = "std")]
use std::fs;
#[cfg(feature = "std")]
use std::path::PathBuf;

/// Write RGB payment info to file
pub(crate) fn write_rgb_payment_info_file(ldk_data_dir: &PathBuf, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64) {
	let rgb_payment_info_path = ldk_data_dir.clone().join(hex::encode(payment_hash.0));
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
	};
	let serialized_info = serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
	std::fs::write(rgb_payment_info_path, serialized_info).expect("able to write rgb payment info file");
}


/// Filter first_hops for contract_id
pub(crate) fn filter_first_hops(ldk_data_dir: &PathBuf, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>) -> ContractId {
	let rgb_payment_info_path = ldk_data_dir.join(hex::encode(payment_hash.0));
	let serialized_info = fs::read_to_string(rgb_payment_info_path).expect("valid rgb payment info file");
	let rgb_payment_info: RgbPaymentInfo = serde_json::from_str(&serialized_info).expect("valid rgb payment info file");
	let contract_id = rgb_payment_info.contract_id;
	first_hops.retain(|h| {
		let info_file_path = ldk_data_dir.join(hex::encode(&h.channel_id));
		if !info_file_path.exists() {
			return false
		}
		let serialized_info = fs::read_to_string(info_file_path).expect("valid rgb info file");
		let rgb_info: RgbInfo = serde_json::from_str(&serialized_info).expect("valid rgb info file");
		rgb_info.contract_id == contract_id.clone()
	});
	contract_id
}
