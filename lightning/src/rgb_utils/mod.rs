//! A module to provide RGB functionality

pub mod proxy;

use crate::chain::transaction::OutPoint;
use crate::ln::PaymentHash;
use crate::ln::chan_utils::{BuiltCommitmentTransaction, ClosingTransaction, CommitmentTransaction, HTLCOutputInCommitment};
use crate::ln::channelmanager::{ChannelDetails, MsgHandleErrInternal};
use crate::ln::channel::ChannelError;

use amplify::{bmap, bset};
use bitcoin::{OutPoint as BtcOutPoint, TxOut};
use bitcoin::blockdata::transaction::Transaction;
use invoice::ConsignmentEndpoint;
use psbt::{Psbt, PsbtVersion};

use bp::seals::txout::CloseMethod;
use internet2::addr::ServiceAddr;
use lnpbp::chain::Chain;
use rgb20::Asset as Rgb20Asset;
use rgb::prelude::EndpointValueMap;
use rgb::psbt::{RgbExt, RgbInExt};
use rgb::{ContractId, Node, StateTransfer};
use rgb_core::SealEndpoint;
use rgb_rpc::Reveal;
use rgb_rpc::client::Client;
use serde::{Deserialize, Serialize};
use strict_encoding::{strict_deserialize, StrictDecode, StrictEncode};

use std::fs;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

use self::proxy::get_consignment;

/// RGB channel info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbInfo {
	/// Channel contract ID
	pub contract_id: ContractId,
	/// Channel RGB local amount
	pub local_rgb_amount: u64,
	/// Channel RGB remote amount
	pub remote_rgb_amount: u64,
}

/// RGB payment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbPaymentInfo {
	/// RGB contract ID
	pub contract_id: ContractId,
	/// RGB payment amount
	pub amount: u64,
	/// RGB local amount
	pub local_rgb_amount: u64,
	/// RGB remote amount
	pub remote_rgb_amount: u64,
}

/// RGB UTXO
#[derive(Debug, Serialize, Deserialize)]
pub struct RgbUtxo {
	/// Outpoint
	pub outpoint: BtcOutPoint,
	/// Whether the UTXO is colored
	pub colored: bool,
}

/// RGB UTXO list
#[derive(Debug, Serialize, Deserialize)]
pub struct RgbUtxos {
	/// The list of RGB UTXOs
	pub utxos: Vec<RgbUtxo>,
}


pub(crate) fn get_rgb_node_client(ldk_data_dir: &PathBuf) -> Client {
	let port_str = fs::read_to_string(ldk_data_dir.join("rgb_node_port")).expect("able to read");
	let port = port_str.parse::<u16>().unwrap();
	let rgb_network_str = fs::read_to_string(ldk_data_dir.join("rgb_node_network")).expect("able to read");
	let rgb_network = Chain::from_str(&rgb_network_str).unwrap();
	let ip = Ipv4Addr::new(127, 0, 0, 1);
	let rgb_node_endpoint = ServiceAddr::Tcp(SocketAddr::V4(SocketAddrV4::new(ip, port)));
	Client::with(rgb_node_endpoint, "rgb-ln-node".to_string(), rgb_network)
		.expect("Error initializing client")
}

/// Color commitment transaction
pub(crate) fn color_commitment(channel_id: &[u8; 32], funding_outpoint: &OutPoint, commitment_tx: &mut CommitmentTransaction, ldk_data_dir: &PathBuf, counterparty: bool) -> Result<(), ChannelError> {
	let transaction = commitment_tx.clone().built.transaction;
	let mut psbt = Psbt::with(transaction.clone(), PsbtVersion::V0).expect("valid transaction");

	let mut rgb_client = get_rgb_node_client(&ldk_data_dir);

	let (rgb_info, _) = get_rgb_channel_info(&channel_id, ldk_data_dir);

	let chan_id = hex::encode(channel_id);
	let mut beneficiaries: EndpointValueMap = bmap![];
	let mut rgb_offered_htlc = 0;
	let mut rgb_received_htlc = 0;
	let mut last_rgb_payment_info = None;
    let mut htlc_vouts: Vec<u32> = vec![];

	for htlc in commitment_tx.htlcs() {
		let htlc_vout = htlc.transaction_output_index.unwrap();
		htlc_vouts.push(htlc_vout);

		let htlc_payment_hash = hex::encode(&htlc.payment_hash.0);
		let htlc_proxy_id = format!("{chan_id}{htlc_payment_hash}");
		let rgb_payment_info_path = ldk_data_dir.clone().join(htlc_proxy_id);

		let rgb_payment_info_hash_path = ldk_data_dir.clone().join(htlc_payment_hash);
		if rgb_payment_info_hash_path.exists() {
			let mut rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_hash_path);
			rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
			rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
			let serialized_info = serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(&rgb_payment_info_path, serialized_info).expect("able to write rgb payment info file");
			fs::remove_file(rgb_payment_info_hash_path).expect("able to remove file");
		}

		let rgb_payment_info = if rgb_payment_info_path.exists() {
			parse_rgb_payment_info(&rgb_payment_info_path)
		} else {
			let rgb_payment_info = RgbPaymentInfo {
				contract_id: rgb_info.contract_id,
				amount: htlc.amount_rgb,
				local_rgb_amount: rgb_info.local_rgb_amount,
				remote_rgb_amount: rgb_info.remote_rgb_amount,
			};
			let serialized_info = serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(rgb_payment_info_path, serialized_info).expect("able to write rgb payment info file");
			rgb_payment_info
		};

		if htlc.offered == counterparty {
			rgb_received_htlc += rgb_payment_info.amount
		} else {
			rgb_offered_htlc += rgb_payment_info.amount
		};

		beneficiaries.insert(SealEndpoint::WitnessVout {
			method: CloseMethod::OpretFirst,
			vout: htlc_vout,
			blinding: 777,
		}, rgb_payment_info.amount);

		last_rgb_payment_info = Some(rgb_payment_info);
	}

	let (local_amt, remote_amt) = if let Some(last_rgb_payment_info) = last_rgb_payment_info {
		(last_rgb_payment_info.local_rgb_amount - rgb_offered_htlc, last_rgb_payment_info.remote_rgb_amount - rgb_received_htlc)
	} else {
		(rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount)
	};
	let (vout_p2wpkh_amt, vout_p2wsh_amt) = if counterparty {
		(local_amt, remote_amt)
	} else {
		(remote_amt, local_amt)
	};

	let non_htlc_outputs: Vec<(u32, &TxOut)> = transaction.output.iter().enumerate().filter(|(index, _)| !htlc_vouts.contains(&(*index as u32)))
		.map(|(index, txout)| (index as u32, txout)).collect();
	let (vout_p2wpkh, _) = non_htlc_outputs.iter().find(|(_, txout)| txout.script_pubkey.is_v0_p2wpkh()).unwrap();
	let (vout_p2wsh, _) = non_htlc_outputs.iter().find(|(index, _)| index != vout_p2wpkh).unwrap();

	beneficiaries.insert(
		SealEndpoint::WitnessVout {
			method: CloseMethod::OpretFirst,
			vout: *vout_p2wpkh,
			blinding: 777,
		}, vout_p2wpkh_amt
	);
	beneficiaries.insert(
		SealEndpoint::WitnessVout {
			method: CloseMethod::OpretFirst,
			vout: *vout_p2wsh,
			blinding: 777,
		}, vout_p2wsh_amt
	);

	let input_outpoints_bt: BTreeSet<BtcOutPoint> = bset![
		BtcOutPoint {
			txid: funding_outpoint.txid,
			vout: funding_outpoint.index as u32,
		}
	];

	let contract = rgb_client
		.contract(rgb_info.contract_id, vec![], |_| {}).expect("successful contract call");
	psbt.set_rgb_contract(contract.clone()).expect("valid contract");
	let consignment_path = ldk_data_dir.join(format!("consignment_{}_revealed", funding_outpoint.txid));
	let transfer = if consignment_path.exists() {
		StateTransfer::strict_file_load(&consignment_path).expect("ok")
	} else {
		let consignment = rgb_client
			.consign(rgb_info.contract_id, vec![], input_outpoints_bt.clone(), |_| ())
			.expect("valid consign call");
		consignment.strict_file_save(consignment_path.clone()).expect("consignment save ok");
		consignment
	};
	let rgb_asset = Rgb20Asset::try_from(&transfer)
		.expect("to have provided a valid consignment");
	let transition = rgb_asset.transfer_static(input_outpoints_bt.clone(), beneficiaries.clone(), bmap![])
		.expect("transfer should succeed");
	psbt.push_rgb_transition(transition.clone()).expect("valid transition");
	let node_id = transition.node_id();
	for input in &mut psbt.inputs {
		if input_outpoints_bt.contains(&input.previous_outpoint) {
			input
				.set_rgb_consumer(rgb_info.contract_id, node_id)
				.expect("set rgb consumer");
		}
	}
	let _count = psbt.rgb_bundle_to_lnpbp4().expect("bundle ok");
	psbt.outputs
		.last_mut()
		.expect("PSBT should have outputs")
		.set_opret_host()
		.expect("given output should be valid");
	let endseals = beneficiaries.into_iter().map(|b| b.0).collect();
	let transfers = vec![(transfer, endseals)];
	let transfer_consignment = rgb_client
		.finalize_transfers_static(transfers, psbt.clone(), |_| ())
		.expect("finalize should succeed");
	let psbt = transfer_consignment.psbt;
	let consignment = &transfer_consignment.consignments[0];

	let modified_tx = psbt.into_unsigned_tx();
	let txid = modified_tx.txid();
	commitment_tx.built = BuiltCommitmentTransaction {
		transaction: modified_tx.clone(),
		txid,
	};

	let consignment_path = ldk_data_dir.join(format!("consignment_{txid}"));
	consignment.strict_file_save(consignment_path.clone()).expect("consignment save ok");

	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc(htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, ldk_data_dir: &PathBuf) -> Result<(), ChannelError> {
	let mut psbt = Psbt::with(htlc_tx.clone(), PsbtVersion::V0).expect("valid transaction");

	let mut rgb_client = get_rgb_node_client(&ldk_data_dir);

	let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
	let consignment_txid = consignment_htlc_outpoint.txid;

	let consignment_path = ldk_data_dir.join(format!("consignment_{}", consignment_txid));
	let commitment_consignment = StateTransfer::strict_file_load(&consignment_path).expect("ok");
	let reveal = Some(Reveal {
		blinding_factor: 777,
		outpoint: consignment_htlc_outpoint,
		close_method: CloseMethod::OpretFirst,
		witness_vout: true,
	});
	let _status = rgb_client.consume_transfer(commitment_consignment.clone(), true, reveal, |_| ())
		.expect("valid register contract");

	let beneficiaries = bmap![
		SealEndpoint::WitnessVout {
			method: CloseMethod::OpretFirst,
			vout: 0,
			blinding: 777,
		} => htlc.amount_rgb
	];

	let input_outpoints_bt: BTreeSet<BtcOutPoint> = bset![
		BtcOutPoint {
			txid: consignment_txid,
			vout: htlc_tx.input.first().unwrap().previous_output.vout,
		}
	];

	let outpoint_state = rgb_client.outpoint_state(input_outpoints_bt.clone(), |_| {}).expect("outpoint state");
	let contract_id = outpoint_state.first_key_value().expect("contract id").0.clone();

	let contract = rgb_client
		.contract(contract_id, vec![], |_| {}).expect("successful contract call");
	psbt.set_rgb_contract(contract.clone()).expect("valid contract");
	let transfer = rgb_client
		.consign(contract_id, vec![], input_outpoints_bt.clone(), |_| ())
		.expect("valid consign call");
	let rgb_asset = Rgb20Asset::try_from(&transfer)
		.expect("to have provided a valid consignment");
	let transition = rgb_asset.transfer_static(input_outpoints_bt.clone(), beneficiaries.clone(), bmap![])
		.expect("transfer should succeed");
	psbt.push_rgb_transition(transition.clone()).expect("valid transition");
	let node_id = transition.node_id();
	for input in &mut psbt.inputs {
		if input_outpoints_bt.contains(&input.previous_outpoint) {
			input
				.set_rgb_consumer(contract_id, node_id)
				.expect("set rgb consumer");
		}
	}
	let _count = psbt.rgb_bundle_to_lnpbp4().expect("bundle ok");
	psbt.outputs
		.last_mut()
		.expect("PSBT should have outputs")
		.set_opret_host()
		.expect("given output should be valid");
	let endseals = beneficiaries.into_iter().map(|b| b.0).collect();
	let transfers = vec![(transfer, endseals)];
	let transfer_consignment = rgb_client
		.finalize_transfers_static(transfers, psbt.clone(), |_| ())
		.expect("finalize should succeed");
	let psbt = transfer_consignment.psbt;
	let consignment = &transfer_consignment.consignments[0];

	let modified_tx = psbt.into_unsigned_tx();
	let modified_txid = &modified_tx.txid();
	*htlc_tx = modified_tx;

	let consignment_path = ldk_data_dir.join(format!("consignment_{}", modified_txid));
	consignment.strict_file_save(consignment_path.clone()).expect("consignment save ok");

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing(channel_id: &[u8; 32], funding_outpoint: &OutPoint, closing_tx: &mut ClosingTransaction, ldk_data_dir: &PathBuf) -> Result<(), ChannelError> {
	let transaction = closing_tx.clone().built;
	let mut psbt = Psbt::with(transaction.clone(), PsbtVersion::V0).expect("valid transaction");

	let mut rgb_client = get_rgb_node_client(&ldk_data_dir);

	let (rgb_info, _) = get_rgb_channel_info(&channel_id, ldk_data_dir);

	let holder_vout = transaction.output.iter().position(|o| o.script_pubkey == closing_tx.to_holder_script).unwrap();
	let counterparty_vout = holder_vout ^ 1;

	let holder_vout_amount = rgb_info.local_rgb_amount;
	let counterparty_vout_amount = rgb_info.remote_rgb_amount;

	let beneficiaries = bmap![
		SealEndpoint::WitnessVout {
			method: CloseMethod::OpretFirst,
			vout: holder_vout as u32,
			blinding: 777,
		} => holder_vout_amount,
		SealEndpoint::WitnessVout {
			method: CloseMethod::OpretFirst,
			vout: counterparty_vout as u32,
			blinding: 777,
		} => counterparty_vout_amount
	];

	let input_outpoints_bt: BTreeSet<BtcOutPoint> = bset![
		BtcOutPoint {
			txid: funding_outpoint.txid,
			vout: funding_outpoint.index as u32,
		}
	];

	let contract = rgb_client
		.contract(rgb_info.contract_id, vec![], |_| {}).expect("successful contract call");
	psbt.set_rgb_contract(contract.clone()).expect("valid contract");
	let consignment_path = ldk_data_dir.join(format!("consignment_{}_revealed", funding_outpoint.txid));
	let transfer = StateTransfer::strict_file_load(&consignment_path).expect("ok");
	let rgb_asset = Rgb20Asset::try_from(&transfer)
		.expect("to have provided a valid consignment");
	let transition = rgb_asset.transfer_static(input_outpoints_bt.clone(), beneficiaries.clone(), bmap![])
		.expect("transfer should succeed");
	psbt.push_rgb_transition(transition.clone()).expect("valid transition");
	let node_id = transition.node_id();
	for input in &mut psbt.inputs {
		if input_outpoints_bt.contains(&input.previous_outpoint) {
			input
				.set_rgb_consumer(rgb_info.contract_id, node_id)
				.expect("set rgb consumer");
		}
	}
	let _count = psbt.rgb_bundle_to_lnpbp4().expect("bundle ok");
	psbt.outputs
		.last_mut()
		.expect("PSBT should have outputs")
		.set_opret_host()
		.expect("given output should be valid");
	let endseals = beneficiaries.into_iter().map(|b| b.0).collect();
	let transfers = vec![(transfer, endseals)];
	let transfer_consignment = rgb_client
		.finalize_transfers_static(transfers, psbt.clone(), |_| ())
		.expect("finalize should succeed");
	let psbt = transfer_consignment.psbt;
	let consignment = &transfer_consignment.consignments[0];

	let modified_tx = psbt.into_unsigned_tx();
	closing_tx.built = modified_tx.clone();

	let consignment_path = ldk_data_dir.join(format!("consignment_{}", modified_tx.txid()));
	consignment.strict_file_save(consignment_path.clone()).expect("consignment save ok");

	Ok(())
}

/// Get RgbPaymentInfo file
pub fn get_rgb_payment_info(payment_hash: &PaymentHash, ldk_data_dir: &PathBuf) -> RgbPaymentInfo {
	let rgb_payment_info_path = ldk_data_dir.join(hex::encode(payment_hash.0));
	parse_rgb_payment_info(&rgb_payment_info_path)
}

/// Parse RgbPaymentInfo
pub fn parse_rgb_payment_info(rgb_payment_info_path: &PathBuf) -> RgbPaymentInfo {
	let serialized_info = fs::read_to_string(&rgb_payment_info_path).expect("valid rgb payment info");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Get RgbInfo file
pub fn get_rgb_channel_info(channel_id: &[u8; 32], ldk_data_dir: &PathBuf) -> (RgbInfo, PathBuf) {
	let info_file_path = ldk_data_dir.join(hex::encode(channel_id));
	let serialized_info = fs::read_to_string(&info_file_path).expect("valid rgb info file");
	let info: RgbInfo = serde_json::from_str(&serialized_info).expect("valid rgb info file");
	(info, info_file_path)
}

/// Write RgbInfo file
pub fn write_rgb_channel_info(path: &PathBuf, rgb_info: &RgbInfo) {
	let serialized_info = serde_json::to_string(&rgb_info).expect("valid rgb info");
	fs::write(path, serialized_info).expect("able to write")
}

/// Write RGB payment info to file
pub fn write_rgb_payment_info_file(ldk_data_dir: &PathBuf, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64) {
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

/// Rename RGB files from temporary to final channel ID
pub(crate) fn rename_rgb_files(channel_id: &[u8; 32], temporary_channel_id: &[u8; 32], ldk_data_dir: &PathBuf) {
	let temp_chan_id = hex::encode(temporary_channel_id);
	let chan_id = hex::encode(channel_id);

	let temporary_channel_id_path = ldk_data_dir.join(&temp_chan_id);
	let channel_id_path = ldk_data_dir.join(&chan_id);
	fs::rename(temporary_channel_id_path, channel_id_path).expect("rename ok");

	let funding_consignment_tmp = ldk_data_dir.join(format!("consignment_{}", temp_chan_id));
	if funding_consignment_tmp.exists() {
		let funding_consignment = ldk_data_dir.join(format!("consignment_{}", chan_id));
		fs::rename(funding_consignment_tmp, funding_consignment).expect("rename ok");
	}
}

/// Handle funding on the receiver side
pub(crate) fn handle_funding(temporary_channel_id: &[u8; 32], funding_txid: String, ldk_data_dir: &PathBuf, consignment_endpoint: ConsignmentEndpoint) -> Result<(), MsgHandleErrInternal> {
	let consignment_endpoint_str = format!("{consignment_endpoint}");
	let (_, proxy_url) = consignment_endpoint_str.split_once(":").unwrap();
	let consignment_res = get_consignment(proxy_url, funding_txid.to_string());
	if consignment_res.is_err() || consignment_res.as_ref().unwrap().result.as_ref().is_none() {
		return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find RGB consignment".to_owned(), *temporary_channel_id));
	}
	let consignment = consignment_res.expect("successful get_consignment proxy call").result.expect("result");
	let consignment_bytes = base64::decode(consignment).expect("valid consignment");
	let consignment: StateTransfer = strict_deserialize(&consignment_bytes).expect("valid consignment");

	let consignment_path = ldk_data_dir.join(format!("consignment_{}", funding_txid));
	consignment.strict_file_save(consignment_path.clone()).expect("consignment save ok");

	let funding_outpoint = format!("{}:0", funding_txid);
	let outpoint = BtcOutPoint::from_str(&funding_outpoint).expect("valid funding outpoint");
	let reveal = Some(Reveal {
		blinding_factor: 777,
		outpoint,
		close_method: CloseMethod::OpretFirst,
		witness_vout: true,
	});

	let mut rgb_client = get_rgb_node_client(&ldk_data_dir);
	let _status = rgb_client.consume_transfer(consignment.clone(), true, reveal, |_| ())
		.expect("valid register contract");
	let contract_id = consignment.contract_id();
	let contract_state = rgb_client
		.contract_state(contract_id)
		.expect("valid contract state");
	let funding_assignment = contract_state.owned_values.iter().find(|ov| ov.seal.txid.to_string() == funding_txid.to_string() && ov.seal.vout == 0).expect("to find funding tx assignment");
	let remote_rgb_amount = funding_assignment.state.value;
	let rgb_info_path = ldk_data_dir.join(hex::encode(temporary_channel_id));
	let rgb_info = RgbInfo {
		contract_id,
		local_rgb_amount: 0,
		remote_rgb_amount,
	};
	write_rgb_channel_info(&rgb_info_path, &rgb_info);

	Ok(())
}

/// Update RGB channel amount
pub(crate) fn update_rgb_channel_amount(channel_id: &[u8; 32], rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &PathBuf) {
	let (mut rgb_info, info_file_path) = get_rgb_channel_info(channel_id, ldk_data_dir);

	if rgb_offered_htlc > rgb_received_htlc {
		let spent = rgb_offered_htlc - rgb_received_htlc;
		rgb_info.local_rgb_amount -= spent;
		rgb_info.remote_rgb_amount += spent;
	} else {
		let received = rgb_received_htlc - rgb_offered_htlc;
		rgb_info.local_rgb_amount += received;
		rgb_info.remote_rgb_amount -= received;
	}

	write_rgb_channel_info(&info_file_path, &rgb_info)
}

/// Filter first_hops for contract_id
pub(crate) fn filter_first_hops(ldk_data_dir: &PathBuf, payment_hash: &PaymentHash, first_hops: &mut Vec<&ChannelDetails>) -> ContractId {
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
