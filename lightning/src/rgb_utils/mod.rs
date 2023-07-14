//! A module to provide RGB functionality

pub mod proxy;

use crate::chain::transaction::OutPoint;
use crate::ln::PaymentHash;
use crate::ln::chan_utils::{BuiltCommitmentTransaction, ClosingTransaction, CommitmentTransaction, HTLCOutputInCommitment};
use crate::ln::channelmanager::{ChannelDetails, MsgHandleErrInternal};
use crate::ln::channel::ChannelError;

use alloc::collections::BTreeMap;
use amplify::none;
use bitcoin::{OutPoint as BtcOutPoint, TxOut, Script};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin_30::psbt::PartiallySignedTransaction as RgbPsbt;
use bitcoin_30::hashes::Hash;
use bp::Outpoint as RgbOutpoint;
use bp::Txid as BpTxid;
use bp::seals::txout::CloseMethod;
use commit_verify::mpc::MerkleBlock;
use rgb::Runtime;
use rgb_core::validation::Validity;
use rgb_core::{Operation, Assign, Anchor, TransitionBundle};
use seals::txout::TxPtr;
use seals::txout::blind::BlindSeal;
use serde::{Deserialize, Serialize};
use rgbstd::{Chain, Txid as RgbTxid};
use rgbstd::containers::{Transfer as RgbTransfer, Bindle, BuilderSeal};
use rgbstd::contract::{ContractId, GraphSeal};
use rgbstd::interface::TypedState;
use rgbstd::persistence::Inventory;
use rgbstd::validation::ConsignmentApi;
use rgbwallet::RgbTransport;
use rgbwallet::psbt::{PsbtDbc, RgbExt, RgbInExt};
use rgbwallet::psbt::opret::OutputOpret;
use strict_encoding::{TypeName, FieldName};

use std::fs::{self, OpenOptions};
use std::convert::TryFrom;
use std::path::{PathBuf, Path};
use std::str::FromStr;
use std::{thread, time};


use self::proxy::get_consignment;

/// Static blinding costant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;

const RGB_RUNTIME_LOCK_FILE: &str = "rgb_runtime.lock";

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
	/// Override RGB amount in route
	pub override_route_amount: Option<u64>,
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

/// RGB transfer info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferInfo {
	/// Transfer anchor
	pub anchor: Anchor<MerkleBlock>,
	/// Transfer bundles
	pub bundles: BTreeMap<ContractId, TransitionBundle>,
	/// Transfer contract ID
	pub contract_id: ContractId,
	/// Transfer vout
	pub vout: u32,
}

/// Get an instance of the RGB runtime
pub fn get_rgb_runtime(ldk_data_dir: &Path) -> Runtime {
	let rgb_network_str = fs::read_to_string(ldk_data_dir.join("rgb_network")).expect("able to read");
	let electrum_url = fs::read_to_string(ldk_data_dir.join("electrum_url")).expect("able to read");
	let lock_file_path = ldk_data_dir.join(RGB_RUNTIME_LOCK_FILE);
	loop {
		match OpenOptions::new().write(true).create_new(true).open(lock_file_path.clone()) {
			Ok(_) => break,
			Err(_) => thread::sleep(time::Duration::from_millis(400)),
		}
	}
	Runtime::load(
		ldk_data_dir.to_path_buf(),
		Chain::from_str(&rgb_network_str).unwrap(),
		&electrum_url).expect("RGB runtime should be available")
}

/// Drop the lock file for write access to the RGB runtime
pub fn drop_rgb_runtime(ldk_data_dir: &Path) {
	fs::remove_file(ldk_data_dir.join(RGB_RUNTIME_LOCK_FILE)).expect("should be able to delete file")
}

/// Read TransferInfo file
pub fn read_rgb_transfer_info(path: &str) -> TransferInfo {
	let serialized_info = fs::read_to_string(path).expect("able to read transfer info file");
	serde_json::from_str(&serialized_info).expect("valid transfer info")
}

/// Whether a transfer is colored
pub fn is_transfer_colored(path: &str) -> bool {
	PathBuf::from(path).exists()
}

/// Write TransferInfo file
pub fn write_rgb_transfer_info(path: &PathBuf, info: &TransferInfo) {
	let serialized_info = serde_json::to_string(&info).expect("valid transfer info");
	fs::write(path, serialized_info).expect("able to write transfer info file")
}

/// Color commitment transaction
pub(crate) fn color_commitment(channel_id: &[u8; 32], funding_outpoint: &OutPoint, commitment_tx: &mut CommitmentTransaction, ldk_data_dir: &Path, counterparty: bool) -> Result<(), ChannelError> {
	let mut transaction = commitment_tx.clone().built.transaction;
	transaction.output.push(TxOut { value: 0, script_pubkey: Script::new_op_return(&[1]) });
	let psbt = PartiallySignedTransaction::from_unsigned_tx(transaction.clone()).expect("valid transaction");
	let mut psbt = RgbPsbt::from_str(&psbt.to_string()).unwrap();

	let mut runtime = get_rgb_runtime(ldk_data_dir);

	let (rgb_info, _) = get_rgb_channel_info(channel_id, ldk_data_dir);

	let chan_id = hex::encode(channel_id);
	let mut beneficiaries = vec![];
	let mut rgb_offered_htlc = 0;
	let mut rgb_received_htlc = 0;
	let mut last_rgb_payment_info = None;
	let mut htlc_vouts: Vec<u32> = vec![];
	let mut asset_transition_builder = runtime.transition_builder(rgb_info.contract_id, TypeName::try_from("RGB20").unwrap(), None::<&str>).expect("ok");
	let assignment_id = asset_transition_builder
		.assignments_type(&FieldName::from("beneficiary")).expect("valid assignment");

	for htlc in commitment_tx.htlcs() {
		let htlc_vout = htlc.transaction_output_index.unwrap();
		htlc_vouts.push(htlc_vout);

		let htlc_payment_hash = hex::encode(htlc.payment_hash.0);
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
				amount: htlc.amount_rgb.unwrap(),
				local_rgb_amount: rgb_info.local_rgb_amount,
				remote_rgb_amount: rgb_info.remote_rgb_amount,
				override_route_amount: None,
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

		let htlc_seal = BuilderSeal::Revealed(GraphSeal::with_vout(CloseMethod::OpretFirst, htlc_vout, STATIC_BLINDING));
		beneficiaries.push(htlc_seal);
		asset_transition_builder = asset_transition_builder
			.add_raw_state_static(assignment_id, htlc_seal, TypedState::Amount(rgb_payment_info.amount)).expect("ok");

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

	let seal_p2wpkh = BuilderSeal::Revealed(GraphSeal::with_vout(CloseMethod::OpretFirst, *vout_p2wpkh, STATIC_BLINDING));
	beneficiaries.push(seal_p2wpkh);
	asset_transition_builder = asset_transition_builder
		.add_raw_state_static(assignment_id, seal_p2wpkh, TypedState::Amount(vout_p2wpkh_amt)).expect("ok");
	let seal_p2wsh = BuilderSeal::Revealed(GraphSeal::with_vout(CloseMethod::OpretFirst, *vout_p2wsh, STATIC_BLINDING));
	beneficiaries.push(seal_p2wsh);
	asset_transition_builder = asset_transition_builder
		.add_raw_state_static(assignment_id, seal_p2wsh, TypedState::Amount(vout_p2wsh_amt)).expect("ok");

	let prev_outputs = psbt
		.unsigned_tx
		.input
		.iter()
		.map(|txin| txin.previous_output)
		.map(|outpoint| RgbOutpoint::new(outpoint.txid.to_byte_array().into(), outpoint.vout))
		.collect::<Vec<_>>();
	for (opout, _state) in runtime.state_for_outpoints(rgb_info.contract_id, prev_outputs.iter().copied()).expect("ok") {
		asset_transition_builder = asset_transition_builder.add_input(opout).expect("valid input");
	}
	let transition = asset_transition_builder
		.complete_transition(rgb_info.contract_id).expect("should complete transition");
	let inputs = vec![RgbOutpoint::new(RgbTxid::from_str(&funding_outpoint.txid.to_string()).unwrap(), funding_outpoint.index as u32)];
	for (input, txin) in psbt.inputs.iter_mut().zip(&psbt.unsigned_tx.input) {
		let prevout = txin.previous_output;
		let outpoint = RgbOutpoint::new(prevout.txid.to_byte_array().into(), prevout.vout);
		if inputs.contains(&outpoint) {
			input.set_rgb_consumer(rgb_info.contract_id, transition.id()).expect("ok");
		}
	}
	psbt.push_rgb_transition(transition).expect("ok");
	let bundles = psbt.rgb_bundles().expect("able to get bundles");
	let (opreturn_index, _) = psbt
		.unsigned_tx
		.output
		.iter()
		.enumerate()
		.find(|(_, o)| o.script_pubkey.is_op_return())
		.expect("psbt should have an op_return output");
	let (_, opreturn_output) = psbt
		.outputs
		.iter_mut()
		.enumerate()
		.find(|(i, _)| i == &opreturn_index)
		.unwrap();
	opreturn_output
		.set_opret_host()
		.expect("cannot set opret host");
	psbt.rgb_bundle_to_lnpbp4().expect("ok");
	let anchor = psbt.dbc_conclude_static(CloseMethod::OpretFirst).expect("should conclude");

	drop(runtime);
	drop_rgb_runtime(ldk_data_dir);

	let psbt = PartiallySignedTransaction::from_str(&psbt.to_string()).unwrap();
	let modified_tx = psbt.extract_tx();
	let txid = modified_tx.txid();
	commitment_tx.built = BuiltCommitmentTransaction {
		transaction: modified_tx.clone(),
		txid,
	};

	// save RGB transfer data to disk
	let transfer_info = TransferInfo {
		anchor,
		bundles,
		contract_id: rgb_info.contract_id,
		vout: *vout_p2wpkh,
	};
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc(htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, ldk_data_dir: &Path) -> Result<(), ChannelError> {
	htlc_tx.output.push(TxOut { value: 0, script_pubkey: Script::new_op_return(&[1]) });
	let psbt = PartiallySignedTransaction::from_unsigned_tx(htlc_tx.clone()).expect("valid transaction");
	let mut psbt = RgbPsbt::from_str(&psbt.to_string()).unwrap();

	let mut runtime = get_rgb_runtime(ldk_data_dir);

	let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
	let commitment_txid = consignment_htlc_outpoint.txid;

	let transfer_info_path = ldk_data_dir.join(format!("{}_transfer_info", commitment_txid));
	let transfer_info = read_rgb_transfer_info(transfer_info_path.to_str().expect("valid transfer into file path"));
	let contract_id = transfer_info.contract_id;

	let mut beneficiaries = vec![];
	let mut asset_transition_builder = runtime.transition_builder(contract_id, TypeName::try_from("RGB20").unwrap(), None::<&str>).expect("ok");
	let assignment_id = asset_transition_builder
		.assignments_type(&FieldName::from("beneficiary")).expect("valid assignment");

	let seal_vout = 0;
	let seal = BuilderSeal::Revealed(GraphSeal::with_vout(CloseMethod::OpretFirst, seal_vout, STATIC_BLINDING));
	beneficiaries.push(seal);
	asset_transition_builder = asset_transition_builder
		.add_raw_state_static(assignment_id, seal, TypedState::Amount(htlc.amount_rgb.expect("this is a rgb channel"))).expect("ok");

	let prev_outputs = psbt
		.unsigned_tx
		.input
		.iter()
		.map(|txin| txin.previous_output)
		.map(|outpoint| RgbOutpoint::new(outpoint.txid.to_byte_array().into(), outpoint.vout))
		.collect::<Vec<_>>();
	for (opout, _state) in runtime.state_for_outpoints(contract_id, prev_outputs.iter().copied()).expect("ok") {
		asset_transition_builder = asset_transition_builder.add_input(opout).expect("valid input");
	}
	let transition = asset_transition_builder
		.complete_transition(contract_id).expect("should complete transition");
	let inputs = vec![RgbOutpoint::new(RgbTxid::from_str(&commitment_txid.to_string()).unwrap(), htlc_tx.input.first().unwrap().previous_output.vout)];
	for (input, txin) in psbt.inputs.iter_mut().zip(&psbt.unsigned_tx.input) {
		let prevout = txin.previous_output;
		let outpoint = RgbOutpoint::new(prevout.txid.to_byte_array().into(), prevout.vout);
		if inputs.contains(&outpoint) {
			input.set_rgb_consumer(contract_id, transition.id()).expect("ok");
		}
	}
	psbt.push_rgb_transition(transition).expect("ok");
	let bundles = psbt.rgb_bundles().expect("able to get bundles");
	let (opreturn_index, _) = psbt
		.unsigned_tx
		.output
		.iter()
		.enumerate()
		.find(|(_, o)| o.script_pubkey.is_op_return())
		.expect("psbt should have an op_return output");
	let (_, opreturn_output) = psbt
		.outputs
		.iter_mut()
		.enumerate()
		.find(|(i, _)| i == &opreturn_index)
		.unwrap();
	opreturn_output
		.set_opret_host()
		.expect("cannot set opret host");
	psbt.rgb_bundle_to_lnpbp4().expect("ok");
	let anchor = psbt.dbc_conclude_static(CloseMethod::OpretFirst).expect("should conclude");

	drop(runtime);
	drop_rgb_runtime(ldk_data_dir);

	let psbt = PartiallySignedTransaction::from_str(&psbt.to_string()).unwrap();
	let modified_tx = psbt.extract_tx();
	let modified_txid = &modified_tx.txid();
	*htlc_tx = modified_tx;

	// save RGB transfer data to disk
	let transfer_info = TransferInfo {
		anchor,
		bundles,
		contract_id,
		vout: seal_vout,
	};
	let transfer_info_path = ldk_data_dir.join(format!("{modified_txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing(channel_id: &[u8; 32], funding_outpoint: &OutPoint, closing_tx: &mut ClosingTransaction, ldk_data_dir: &Path) -> Result<(), ChannelError> {
	let mut transaction = closing_tx.clone().built;
	transaction.output.push(TxOut { value: 0, script_pubkey: Script::new_op_return(&[1]) });
	let psbt = PartiallySignedTransaction::from_unsigned_tx(transaction.clone()).expect("valid transaction");
	let mut psbt = RgbPsbt::from_str(&psbt.to_string()).unwrap();

	let mut runtime = get_rgb_runtime(ldk_data_dir);

	let (rgb_info, _) = get_rgb_channel_info(channel_id, ldk_data_dir);

	let holder_vout = transaction.output.iter().position(|o| o.script_pubkey == closing_tx.to_holder_script).unwrap();
	let counterparty_vout = holder_vout ^ 1;

	let holder_vout_amount = rgb_info.local_rgb_amount;
	let counterparty_vout_amount = rgb_info.remote_rgb_amount;

	let mut beneficiaries = vec![];
	let mut asset_transition_builder = runtime.transition_builder(rgb_info.contract_id, TypeName::try_from("RGB20").unwrap(), None::<&str>).expect("ok");
	let assignment_id = asset_transition_builder
		.assignments_type(&FieldName::from("beneficiary")).expect("valid assignment");

	let holder_seal = BuilderSeal::Revealed(GraphSeal::with_vout(CloseMethod::OpretFirst, holder_vout as u32, STATIC_BLINDING));
	beneficiaries.push(holder_seal);
	asset_transition_builder = asset_transition_builder
		.add_raw_state_static(assignment_id, holder_seal, TypedState::Amount(holder_vout_amount)).expect("ok");
	let counterparty_seal = BuilderSeal::Revealed(GraphSeal::with_vout(CloseMethod::OpretFirst, counterparty_vout as u32, STATIC_BLINDING));
	beneficiaries.push(counterparty_seal);
	asset_transition_builder = asset_transition_builder
		.add_raw_state_static(assignment_id, counterparty_seal, TypedState::Amount(counterparty_vout_amount)).expect("ok");

	let prev_outputs = psbt
		.unsigned_tx
		.input
		.iter()
		.map(|txin| txin.previous_output)
		.map(|outpoint| RgbOutpoint::new(outpoint.txid.to_byte_array().into(), outpoint.vout))
		.collect::<Vec<_>>();
	for (opout, _state) in runtime.state_for_outpoints(rgb_info.contract_id, prev_outputs.iter().copied()).expect("ok") {
		asset_transition_builder = asset_transition_builder.add_input(opout).expect("valid input");
	}
	let transition = asset_transition_builder
		.complete_transition(rgb_info.contract_id).expect("should complete transition");
	let inputs = vec![RgbOutpoint::new(RgbTxid::from_str(&funding_outpoint.txid.to_string()).unwrap(), funding_outpoint.index as u32)];
	for (input, txin) in psbt.inputs.iter_mut().zip(&psbt.unsigned_tx.input) {
		let prevout = txin.previous_output;
		let outpoint = RgbOutpoint::new(prevout.txid.to_byte_array().into(), prevout.vout);
		if inputs.contains(&outpoint) {
			input.set_rgb_consumer(rgb_info.contract_id, transition.id()).expect("ok");
		}
	}
	psbt.push_rgb_transition(transition).expect("ok");
	let bundles = psbt.rgb_bundles().expect("able to get bundles");
	let (opreturn_index, _) = psbt
		.unsigned_tx
		.output
		.iter()
		.enumerate()
		.find(|(_, o)| o.script_pubkey.is_op_return())
		.expect("psbt should have an op_return output");
	let (_, opreturn_output) = psbt
		.outputs
		.iter_mut()
		.enumerate()
		.find(|(i, _)| i == &opreturn_index)
		.unwrap();
	opreturn_output
		.set_opret_host()
		.expect("cannot set opret host");
	psbt.rgb_bundle_to_lnpbp4().expect("ok");
	let anchor = psbt.dbc_conclude_static(CloseMethod::OpretFirst).expect("should conclude");

	drop(runtime);
	drop_rgb_runtime(ldk_data_dir);

	let psbt = PartiallySignedTransaction::from_str(&psbt.to_string()).unwrap();
	let modified_tx = psbt.extract_tx();
	let txid = modified_tx.txid();
	closing_tx.built = modified_tx.clone();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo {
		anchor,
		bundles,
		contract_id: rgb_info.contract_id,
		vout: holder_vout as u32,
	};
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Get RgbPaymentInfo file
pub fn get_rgb_payment_info(payment_hash: &PaymentHash, ldk_data_dir: &Path) -> RgbPaymentInfo {
	let rgb_payment_info_path = ldk_data_dir.join(hex::encode(payment_hash.0));
	parse_rgb_payment_info(&rgb_payment_info_path)
}

/// Parse RgbPaymentInfo
pub fn parse_rgb_payment_info(rgb_payment_info_path: &PathBuf) -> RgbPaymentInfo {
	let serialized_info = fs::read_to_string(rgb_payment_info_path).expect("valid rgb payment info");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Get RgbInfo file
pub fn get_rgb_channel_info(channel_id: &[u8; 32], ldk_data_dir: &Path) -> (RgbInfo, PathBuf) {
	let info_file_path = ldk_data_dir.join(hex::encode(channel_id));
	let serialized_info = fs::read_to_string(&info_file_path).expect("valid rgb info file");
	let info: RgbInfo = serde_json::from_str(&serialized_info).expect("valid rgb info file");
	(info, info_file_path)
}

/// Whether the channel data for a channel exist
pub fn is_channel_rgb(channel_id: &[u8; 32], ldk_data_dir: &PathBuf) -> bool {
	ldk_data_dir.join(hex::encode(channel_id)).exists()
}

/// Write RgbInfo file
pub fn write_rgb_channel_info(path: &PathBuf, rgb_info: &RgbInfo) {
	let serialized_info = serde_json::to_string(&rgb_info).expect("valid rgb info");
	fs::write(path, serialized_info).expect("able to write")
}

/// Write RGB payment info to file
pub fn write_rgb_payment_info_file(ldk_data_dir: &Path, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64, override_route_amount: Option<u64>) {
	let rgb_payment_info_path = ldk_data_dir.join(hex::encode(payment_hash.0));
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
		override_route_amount,
	};
	let serialized_info = serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
	std::fs::write(rgb_payment_info_path, serialized_info).expect("able to write rgb payment info file");
}

/// Rename RGB files from temporary to final channel ID
pub(crate) fn rename_rgb_files(channel_id: &[u8; 32], temporary_channel_id: &[u8; 32], ldk_data_dir: &Path) {
	let temp_chan_id = hex::encode(temporary_channel_id);
	let chan_id = hex::encode(channel_id);

	let temporary_channel_id_path = ldk_data_dir.join(&temp_chan_id);
	let channel_id_path = ldk_data_dir.join(&chan_id);
	fs::rename(temporary_channel_id_path, channel_id_path).expect("rename ok");

	let funding_consignment_tmp = ldk_data_dir.join(format!("consignment_{}", temp_chan_id));
	let funding_consignment = ldk_data_dir.join(format!("consignment_{}", chan_id));
	fs::rename(funding_consignment_tmp, funding_consignment).expect("rename ok");
}

/// Handle funding on the receiver side
pub(crate) fn handle_funding(temporary_channel_id: &[u8; 32], funding_txid: String, ldk_data_dir: &Path, consignment_endpoint: RgbTransport) -> Result<(), MsgHandleErrInternal> {
	let consignment_endpoint_str = format!("{consignment_endpoint}");
	let proxy_url = if consignment_endpoint_str.starts_with("rpc:") {
		let (_, host) = consignment_endpoint_str.split_once(':').unwrap();
		format!("http:{host}")
	} else if consignment_endpoint_str.starts_with("rpcs:") {
		let (_, host) = consignment_endpoint_str.split_once(':').unwrap();
		format!("https:{host}")
	} else {
		panic!("impossible");
	};

	let consignment_res = get_consignment(&proxy_url, funding_txid.clone());
	if consignment_res.is_err() || consignment_res.as_ref().unwrap().result.as_ref().is_none() {
		return Err(MsgHandleErrInternal::send_err_msg_no_close("Failed to find RGB consignment".to_owned(), *temporary_channel_id));
	}
	let consignment = consignment_res.expect("successful get_consignment proxy call").result.expect("result");
	let consignment_bytes = base64::decode(consignment).expect("valid consignment");
	let consignment_path = ldk_data_dir.join(format!("consignment_{}", funding_txid));
	fs::write(consignment_path.clone(), consignment_bytes.clone()).expect("unable to write file");
	let consignment_path = ldk_data_dir.join(format!("consignment_{}", hex::encode(temporary_channel_id)));
	fs::write(consignment_path.clone(), consignment_bytes).expect("unable to write file");
	let consignment = Bindle::<RgbTransfer>::load(consignment_path).expect("successful consignment load");
	let transfer: RgbTransfer = consignment.clone().unbindle();

	let mut runtime = get_rgb_runtime(ldk_data_dir);

	let funding_seal = BlindSeal::with_blinding(CloseMethod::OpretFirst, TxPtr::WitnessTx, 0, STATIC_BLINDING);
	runtime.store_seal_secret(funding_seal).expect("valid seal");

	let validated_transfer = match transfer.clone().validate(runtime.resolver()) {
		Ok(consignment) => consignment,
		Err(consignment) => consignment,
	};
	let validation_status = validated_transfer.clone().into_validation_status().unwrap();
	let validity = validation_status.validity();
	if !vec![Validity::Valid, Validity::UnminedTerminals].contains(&validity) {
		return Err(MsgHandleErrInternal::send_err_msg_no_close("Invalid RGB consignment for funding".to_owned(), *temporary_channel_id));
	}

	let mut minimal_contract = transfer.clone().into_contract();
	minimal_contract.bundles = none!();
	minimal_contract.terminals = none!();
	let minimal_contract_validated = match minimal_contract.clone().validate(runtime.resolver()) {
		Ok(consignment) => consignment,
		Err(consignment) => consignment,
	};
	runtime
		.import_contract(minimal_contract_validated)
		.expect("failure importing issued contract");

	let contract_id = consignment.contract_id();

	let mut remote_rgb_amount = 0;
	for bundle in validated_transfer.anchored_bundles() {
		if bundle.anchor.txid != BpTxid::from_str(&funding_txid).expect("valid txid") {
			continue;
		}
		for bundle_item in bundle.bundle.values() {
			if let Some(transition) = &bundle_item.transition {
				for assignment in transition.assignments.values() {
					for fungible_assignment in assignment.as_fungible() {
						if let Assign::Revealed { seal, state } = fungible_assignment {
							if *seal == funding_seal {
								remote_rgb_amount += state.value.as_u64();
								break;
							}
						};
					}
				}
			}
		}
	};
	let _status = runtime.accept_transfer(validated_transfer.clone(), true).expect("valid transfer");

	drop(runtime);
	drop_rgb_runtime(ldk_data_dir);

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
pub(crate) fn update_rgb_channel_amount(channel_id: &[u8; 32], rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path) {
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

/// Whether the payment is colored
pub(crate) fn is_payment_rgb(ldk_data_dir: &PathBuf, payment_hash: &PaymentHash) -> bool {
	ldk_data_dir.join(hex::encode(payment_hash.0)).exists()
}

/// Filter first_hops for contract_id
pub(crate) fn filter_first_hops(ldk_data_dir: &Path, payment_hash: &PaymentHash, first_hops: &mut Vec<&ChannelDetails>) -> ContractId {
	let rgb_payment_info_path = ldk_data_dir.join(hex::encode(payment_hash.0));
	let serialized_info = fs::read_to_string(rgb_payment_info_path).expect("valid rgb payment info file");
	let rgb_payment_info: RgbPaymentInfo = serde_json::from_str(&serialized_info).expect("valid rgb payment info file");
	let contract_id = rgb_payment_info.contract_id;
	first_hops.retain(|h| {
		let info_file_path = ldk_data_dir.join(hex::encode(h.channel_id));
		if !info_file_path.exists() {
			return false
		}
		let serialized_info = fs::read_to_string(info_file_path).expect("valid rgb info file");
		let rgb_info: RgbInfo = serde_json::from_str(&serialized_info).expect("valid rgb info file");
		rgb_info.contract_id == contract_id
	});
	contract_id
}
