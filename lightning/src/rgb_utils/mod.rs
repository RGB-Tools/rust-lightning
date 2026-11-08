//! A module to provide RGB functionality

// this module uses the online APIs of rgb-lib, which are only available if rgb-lib has been built
// with support for at least one indexer protocol
#[cfg(not(any(feature = "electrum", feature = "esplora")))]
compile_error!("at least one of the `electrum` and `esplora` features needs to be enabled");

use crate::ln::chan_utils::{
	commitment_tx_base_weight, get_countersigner_payment_script, BuiltCommitmentTransaction,
	ClosingTransaction, CommitmentTransaction, HTLCOutputInCommitment,
	COMMITMENT_TX_WEIGHT_PER_HTLC,
};
use crate::ln::channel::{ChannelContext, ChannelError, FundingScope};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::types::ChannelId;
use crate::sign::SignerProvider;
use crate::types::features::ChannelTypeFeatures;
use crate::types::payment::PaymentHash;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::PublicKey;
use bitcoin::TxOut;
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	wallet::{
		rust_only::{AssetColoringInfo, ColoringInfo},
		OnlineOptions, RgbWalletOpsOffline, Wallet,
	},
	AssetSchema, Assignment, ConsignmentExt, ContractId, Error as RgbLibError, RgbTransfer,
	WitnessOrd,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use core::ops::Deref;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Static blinding costant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;
/// Name of the file containing the electrum URL
pub const INDEXER_URL_FNAME: &str = "indexer_url";
/// Name of the file containing the master fingerprint of the wallet
pub const WALLET_MASTER_FINGERPRINT_FNAME: &str = "wallet_master_fingerprint";
const INBOUND_EXT: &str = "inbound";
const OUTBOUND_EXT: &str = "outbound";
const VANILLA_SYNC_LOOKBACK: u32 = 20;

/// RGB channel info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbInfo {
	/// Channel contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Channel schema
	pub schema: AssetSchema,
	/// Channel RGB local amount
	pub local_rgb_amount: u64,
	/// Channel RGB remote amount
	pub remote_rgb_amount: u64,
	/// Batch transfer index from rgb-lib (set after rgb_send_begin)
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub batch_transfer_idx: Option<i32>,
	/// Whether the channel acceptor told us (in `accept_channel`) that it already knows the asset
	#[serde(default)]
	pub counterparty_knows_asset: bool,
}

/// RGB payment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbPaymentInfo {
	/// RGB contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// RGB payment amount
	pub amount: u64,
	/// RGB local amount
	pub local_rgb_amount: u64,
	/// RGB remote amount
	pub remote_rgb_amount: u64,
	/// Whether the RGB amount in route should be overridden
	pub swap_payment: bool,
	/// Whether the payment is inbound
	pub inbound: bool,
}

/// RGB transfer info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferInfo {
	/// Transfer contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// RGB amount assigned to each output of the transaction, by vout
	pub output_map: HashMap<u32, u64>,
}

mod contract_id_serde {
	use super::*;
	use serde::{Deserializer, Serializer};
	use std::str::FromStr;

	pub fn serialize<S>(id: &ContractId, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&id.to_string())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<ContractId, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		ContractId::from_str(&s).map_err(serde::de::Error::custom)
	}
}

fn _get_file_in_parent(ldk_data_dir: &Path, fname: &str) -> PathBuf {
	ldk_data_dir.parent().unwrap().join(fname)
}

fn _read_file_in_parent(ldk_data_dir: &Path, fname: &str) -> String {
	fs::read_to_string(_get_file_in_parent(ldk_data_dir, fname)).unwrap()
}

fn _get_master_fingerprint(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_MASTER_FINGERPRINT_FNAME)
}

fn _get_indexer_url(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, INDEXER_URL_FNAME)
}

fn _load_rgb_wallet(data_dir: String, master_fingerprint: String) -> Wallet {
	Wallet::load(&data_dir, &master_fingerprint, None).expect("valid rgb-lib wallet")
}

fn _get_wallet_data(ldk_data_dir: &Path) -> (String, String) {
	let data_dir = ldk_data_dir.parent().unwrap().to_string_lossy().to_string();
	let master_fingerprint = _get_master_fingerprint(ldk_data_dir);
	(data_dir, master_fingerprint)
}

async fn _get_rgb_wallet(ldk_data_dir: &Path) -> Wallet {
	let (data_dir, master_fingerprint) = _get_wallet_data(ldk_data_dir);
	tokio::task::spawn_blocking(move || _load_rgb_wallet(data_dir, master_fingerprint))
		.await
		.unwrap()
}

pub(crate) fn is_asset_known(contract_id: ContractId, ldk_data_dir: &Path) -> bool {
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	wallet.is_asset_known(contract_id).unwrap_or(false)
}

async fn _accept_transfer(
	ldk_data_dir: &Path, funding_txid: String,
) -> Result<(RgbTransfer, Vec<Assignment>, HashSet<String>, PathBuf), RgbLibError> {
	let funding_vout = 1;
	let (data_dir, master_fingerprint) = _get_wallet_data(ldk_data_dir);
	let indexer_url = _get_indexer_url(ldk_data_dir);
	// the consignment is received from the channel counterparty over the p2p link and written to disk
	let consignment_path = ldk_data_dir.join(format!("consignment_{funding_txid}"));
	tokio::task::spawn_blocking(move || {
		let mut wallet = _load_rgb_wallet(data_dir, master_fingerprint);
		let online = wallet.go_online(OnlineOptions {
			indexer_url,
			skip_consistency_check: true,
			vanilla_sync_lookback: VANILLA_SYNC_LOOKBACK,
		})?;
		let (consignment, assignments, media_digests) = wallet.accept_transfer_consignment(
			online,
			consignment_path,
			funding_txid.clone(),
			funding_vout,
			STATIC_BLINDING,
		)?;
		Ok((consignment, assignments, media_digests, wallet.get_media_dir()))
	})
	.await
	.unwrap()
}

/// Read TransferInfo file
pub fn read_rgb_transfer_info(path: &Path) -> TransferInfo {
	let serialized_info = fs::read_to_string(path).expect("able to read transfer info file");
	serde_json::from_str(&serialized_info).expect("valid transfer info")
}

/// Write TransferInfo file
pub fn write_rgb_transfer_info(path: &PathBuf, info: &TransferInfo) {
	let serialized_info = serde_json::to_string(&info).expect("valid transfer info");
	fs::write(path, serialized_info).expect("able to write transfer info file")
}

fn _counterparty_output_index(
	outputs: &[TxOut], channel_type_features: &ChannelTypeFeatures, payment_key: &PublicKey,
) -> Option<usize> {
	let counterparty_payment_script =
		get_countersigner_payment_script(channel_type_features, payment_key);
	outputs
		.iter()
		.enumerate()
		.find(|(_, out)| out.script_pubkey == counterparty_payment_script)
		.map(|(idx, _)| idx)
}

/// Return the position of the OP_RETURN output, if present
pub fn op_return_position(tx: &Transaction) -> Option<usize> {
	tx.output.iter().position(|o| o.script_pubkey.is_op_return())
}

/// Whether the transaction is colored (i.e. it has an OP_RETURN output)
pub fn is_tx_colored(tx: &Transaction) -> bool {
	op_return_position(tx).is_some()
}

/// Weight of the OP_RETURN output coloring a commitment transaction: 8-byte value, 1-byte script
/// length and 34-byte `OP_RETURN OP_PUSHBYTES_32 <commitment>` script
const COMMITMENT_TX_OP_RETURN_WEIGHT: u64 = 172;

/// Get the fee cost of a colored commitment tx with a given number of HTLC outputs, which includes
/// the weight of the OP_RETURN output.
/// Note that num_htlcs should not include dust HTLCs.
pub(crate) fn colored_commit_tx_fee_sat(
	feerate_per_kw: u32, num_htlcs: usize, channel_type_features: &ChannelTypeFeatures,
) -> u64 {
	feerate_per_kw as u64
		* (commitment_tx_base_weight(channel_type_features)
			+ COMMITMENT_TX_OP_RETURN_WEIGHT
			+ num_htlcs as u64 * COMMITMENT_TX_WEIGHT_PER_HTLC)
		/ 1000
}

/// Color commitment transaction
pub(crate) fn color_commitment<SP: Deref>(
	channel_context: &ChannelContext<SP>, funding_scope: &FundingScope,
	commitment_transaction: &mut CommitmentTransaction, counterparty: bool,
) -> Result<(), ChannelError>
where
	<SP as std::ops::Deref>::Target: SignerProvider,
{
	let channel_id = &channel_context.channel_id;
	let ldk_data_dir = channel_context.ldk_data_dir.as_path();

	let commitment_tx = commitment_transaction.clone().built.transaction;

	let (rgb_info, _) = get_rgb_channel_info_pending(channel_id, ldk_data_dir);
	let contract_id = rgb_info.contract_id;

	let chan_id = channel_id.0.as_hex();
	let mut rgb_offered_htlc = 0;
	let mut rgb_received_htlc = 0;
	let mut last_rgb_payment_info = None;
	let mut output_map = HashMap::new();

	for htlc in commitment_transaction.nondust_htlcs() {
		if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
			continue;
		}
		let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

		let htlc_vout = htlc.transaction_output_index.unwrap();

		let inbound = htlc.offered == counterparty;

		let htlc_payment_hash = htlc.payment_hash.0.as_hex().to_string();
		let htlc_proxy_id = format!("{chan_id}{htlc_payment_hash}");
		let mut rgb_payment_info_proxy_id_path = ldk_data_dir.join(htlc_proxy_id);
		let rgb_payment_info_path = ldk_data_dir.join(htlc_payment_hash);
		let mut rgb_payment_info_path = rgb_payment_info_path.clone();
		if inbound {
			rgb_payment_info_proxy_id_path.set_extension(INBOUND_EXT);
			rgb_payment_info_path.set_extension(INBOUND_EXT);
		} else {
			rgb_payment_info_proxy_id_path.set_extension(OUTBOUND_EXT);
			rgb_payment_info_path.set_extension(OUTBOUND_EXT);
		}
		let rgb_payment_info_tmp_path = _append_pending_extension(&rgb_payment_info_path);

		if rgb_payment_info_tmp_path.exists() {
			let mut rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_tmp_path);
			rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
			rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
			let serialized_info =
				serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(&rgb_payment_info_proxy_id_path, serialized_info)
				.expect("able to write rgb payment info file");
			fs::remove_file(rgb_payment_info_tmp_path).expect("able to remove file");
		}

		let rgb_payment_info = if rgb_payment_info_proxy_id_path.exists() {
			parse_rgb_payment_info(&rgb_payment_info_proxy_id_path)
		} else {
			let rgb_payment_info = RgbPaymentInfo {
				contract_id,
				amount: htlc_amount_rgb,
				local_rgb_amount: rgb_info.local_rgb_amount,
				remote_rgb_amount: rgb_info.remote_rgb_amount,
				swap_payment: true,
				inbound,
			};
			let serialized_info =
				serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(rgb_payment_info_proxy_id_path, serialized_info.clone())
				.expect("able to write rgb payment info file");
			fs::write(rgb_payment_info_path, serialized_info)
				.expect("able to write rgb payment info file");
			rgb_payment_info
		};

		if inbound {
			rgb_received_htlc += rgb_payment_info.amount
		} else {
			rgb_offered_htlc += rgb_payment_info.amount
		};

		output_map.insert(htlc_vout, rgb_payment_info.amount);

		last_rgb_payment_info = Some(rgb_payment_info);
	}

	let (local_amt, remote_amt) = if let Some(last_rgb_payment_info) = last_rgb_payment_info {
		(
			last_rgb_payment_info.local_rgb_amount - rgb_offered_htlc,
			last_rgb_payment_info.remote_rgb_amount - rgb_received_htlc,
		)
	} else {
		(rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount)
	};
	let (vout_p2wpkh_amt, vout_p2wsh_amt) =
		if counterparty { (local_amt, remote_amt) } else { (remote_amt, local_amt) };

	let payment_point = if counterparty {
		funding_scope.get_holder_pubkeys().payment_point
	} else {
		funding_scope.get_counterparty_pubkeys().payment_point
	};

	if let Some(vout_p2wpkh) = _counterparty_output_index(
		&commitment_tx.output,
		funding_scope.get_channel_type(),
		&payment_point,
	) {
		output_map.insert(vout_p2wpkh as u32, vout_p2wpkh_amt);
	}

	if let Some(vout_p2wsh) = commitment_transaction.trust().revokeable_output_index() {
		output_map.insert(vout_p2wsh as u32, vout_p2wsh_amt);
	}

	let asset_coloring_info = AssetColoringInfo {
		output_map: output_map.clone(),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let psbt = Psbt::from_unsigned_tx(commitment_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = modified_tx.compute_txid();
	commitment_transaction.built = BuiltCommitmentTransaction { transaction: modified_tx, txid };

	wallet.consume_fascia(fascia.clone(), Some(WitnessOrd::Ignored)).unwrap();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo { contract_id, output_map };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc(
	htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, ldk_data_dir: &Path,
) -> Result<(), ChannelError> {
	if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
		return Ok(());
	}
	let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

	let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
	let commitment_txid = consignment_htlc_outpoint.txid.to_string();

	let transfer_info_path = ldk_data_dir.join(format!("{commitment_txid}_transfer_info"));
	let transfer_info = read_rgb_transfer_info(&transfer_info_path);
	let contract_id = transfer_info.contract_id;

	let output_map = HashMap::from([(0, htlc_amount_rgb)]);
	let asset_coloring_info = AssetColoringInfo {
		output_map: output_map.clone(),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: Some(1),
	};
	let psbt = Psbt::from_unsigned_tx(htlc_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};
	let txid = &modified_tx.compute_txid();

	wallet.consume_fascia(fascia.clone(), Some(WitnessOrd::Ignored)).unwrap();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo { contract_id, output_map };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing(
	channel_id: &ChannelId, closing_transaction: &mut ClosingTransaction, ldk_data_dir: &Path,
) -> Result<(), ChannelError> {
	let closing_tx = closing_transaction.clone().built;

	let (rgb_info, _) = get_rgb_channel_info_pending(channel_id, ldk_data_dir);
	let contract_id = rgb_info.contract_id;

	let holder_vout_amount = rgb_info.local_rgb_amount;
	let counterparty_vout_amount = rgb_info.remote_rgb_amount;

	let mut output_map = HashMap::new();

	if closing_transaction.to_holder_value_sat() > 0 {
		let holder_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_holder_script())
			.unwrap();
		output_map.insert(holder_vout as u32, holder_vout_amount);
	}

	if closing_transaction.to_counterparty_value_sat() > 0 {
		let counterparty_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_counterparty_script())
			.unwrap();
		output_map.insert(counterparty_vout as u32, counterparty_vout_amount);
	}

	let asset_coloring_info = AssetColoringInfo {
		output_map: output_map.clone(),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let psbt = Psbt::from_unsigned_tx(closing_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = &modified_tx.compute_txid();
	closing_transaction.built = modified_tx;

	wallet.consume_fascia(fascia.clone(), Some(WitnessOrd::Ignored)).unwrap();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo { contract_id, output_map };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Get RgbPaymentInfo file path
pub fn get_rgb_payment_info_path(
	payment_hash: &PaymentHash, ldk_data_dir: &Path, inbound: bool,
) -> PathBuf {
	let mut path = ldk_data_dir.join(payment_hash.0.as_hex().to_string());
	path.set_extension(if inbound { INBOUND_EXT } else { OUTBOUND_EXT });
	path
}

/// Parse RgbPaymentInfo
pub fn parse_rgb_payment_info(rgb_payment_info_path: &PathBuf) -> RgbPaymentInfo {
	let serialized_info =
		fs::read_to_string(rgb_payment_info_path).expect("valid rgb payment info");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Get RgbInfo file path
pub fn get_rgb_channel_info_path(channel_id: &str, ldk_data_dir: &Path, pending: bool) -> PathBuf {
	let mut info_file_path = ldk_data_dir.join(channel_id);
	if pending {
		info_file_path.set_extension("pending");
	}
	info_file_path
}

/// Get RgbInfo file
pub(crate) fn get_rgb_channel_info(
	channel_id: &str, ldk_data_dir: &Path, pending: bool,
) -> (RgbInfo, PathBuf) {
	let info_file_path = get_rgb_channel_info_path(channel_id, ldk_data_dir, pending);
	let info = parse_rgb_channel_info(&info_file_path);
	(info, info_file_path)
}

/// Get pending RgbInfo file
pub fn get_rgb_channel_info_pending(
	channel_id: &ChannelId, ldk_data_dir: &Path,
) -> (RgbInfo, PathBuf) {
	get_rgb_channel_info(&channel_id.0.as_hex().to_string(), ldk_data_dir, true)
}

/// Parse RgbInfo
pub fn parse_rgb_channel_info(rgb_channel_info_path: &PathBuf) -> RgbInfo {
	let serialized_info = fs::read_to_string(rgb_channel_info_path).expect("valid rgb info file");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Whether the channel data for a channel exist
pub fn is_channel_rgb(channel_id: &ChannelId, ldk_data_dir: &Path) -> bool {
	get_rgb_channel_info_path(&channel_id.0.as_hex().to_string(), ldk_data_dir, false).exists()
}

/// Write RgbInfo file
pub fn write_rgb_channel_info(path: &PathBuf, rgb_info: &RgbInfo) {
	let serialized_info = serde_json::to_string(&rgb_info).expect("valid rgb info");
	fs::write(path, serialized_info).expect("able to write")
}

fn _append_pending_extension(path: &Path) -> PathBuf {
	let mut new_path = path.to_path_buf();
	new_path.set_extension(format!("{}_pending", new_path.extension().unwrap().to_string_lossy()));
	new_path
}

/// Write RGB payment info to file
pub fn write_rgb_payment_info_file(
	ldk_data_dir: &Path, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64,
	swap_payment: bool, inbound: bool,
) {
	let rgb_payment_info_path = get_rgb_payment_info_path(payment_hash, ldk_data_dir, inbound);
	let rgb_payment_info_tmp_path = _append_pending_extension(&rgb_payment_info_path);
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
		swap_payment,
		inbound,
	};
	let serialized_info = serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
	std::fs::write(rgb_payment_info_path, serialized_info.clone())
		.expect("able to write rgb payment info file");
	std::fs::write(rgb_payment_info_tmp_path, serialized_info)
		.expect("able to write rgb payment info tmp file");
}

/// Rename RGB files from temporary to final channel ID
pub(crate) fn rename_rgb_files(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, ldk_data_dir: &Path,
) {
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	let chan_id = channel_id.0.as_hex().to_string();

	fs::rename(
		get_rgb_channel_info_path(&temp_chan_id, ldk_data_dir, false),
		get_rgb_channel_info_path(&chan_id, ldk_data_dir, false),
	)
	.expect("rename ok");
	fs::rename(
		get_rgb_channel_info_path(&temp_chan_id, ldk_data_dir, true),
		get_rgb_channel_info_path(&chan_id, ldk_data_dir, true),
	)
	.expect("rename ok");
}

/// Directory holding the media received for a funding, before the contract has vouched for it.
pub fn get_media_staging_dir(ldk_data_dir: &Path, funding_txid: &str) -> PathBuf {
	ldk_data_dir.join(format!("media_staging_{funding_txid}"))
}

/// Handle funding on the receiver side
pub(crate) fn handle_funding(
	temporary_channel_id: &ChannelId, funding_txid: String, ldk_data_dir: &Path,
	push_asset_amount: Option<u64>,
) -> Result<(), ChannelError> {
	let handle = Handle::current();
	let _ = handle.enter();
	let accept_res =
		futures::executor::block_on(_accept_transfer(ldk_data_dir, funding_txid.clone()));
	let (consignment, remote_rgb_assignments, media_digests, media_dir) = match accept_res {
		Ok(res) => res,
		Err(RgbLibError::InvalidConsignment) => {
			return Err(ChannelError::close("Invalid RGB consignment for funding".to_owned()))
		},
		Err(RgbLibError::NoConsignment) => {
			return Err(ChannelError::close("Failed to find RGB consignment".to_owned()))
		},
		Err(RgbLibError::UnknownRgbSchema { schema_id }) => {
			return Err(ChannelError::close(format!("Unknown RGB schema: {schema_id}")))
		},
		Err(RgbLibError::UnsupportedSchema { asset_schema }) => {
			return Err(ChannelError::close(format!("Unsupported RGB schema: {asset_schema}")))
		},
		Err(RgbLibError::Indexer { details })
		| Err(RgbLibError::InvalidIndexer { details })
		| Err(RgbLibError::Network { details }) => {
			return Err(ChannelError::close(format!("Failed to connect to indexer: {details}")))
		},
		Err(e) => return Err(ChannelError::close(format!("Unexpected error: {e}"))),
	};

	let staging_dir = get_media_staging_dir(ldk_data_dir, &funding_txid);
	for digest in media_digests {
		let media_path = media_dir.join(&digest);
		if media_path.exists() {
			continue;
		}
		let staged_path = staging_dir.join(&digest);
		let Ok(media_bytes) = fs::read(&staged_path) else {
			return Err(ChannelError::close(format!(
				"Missing RGB media file {digest} for funding"
			)));
		};
		if sha256::Hash::hash(&media_bytes).to_string() != digest {
			return Err(ChannelError::close(format!(
				"Corrupt RGB media file {digest} for funding"
			)));
		}
		if let Err(e) = fs::rename(&staged_path, &media_path) {
			return Err(ChannelError::close(format!(
				"Failed to store RGB media file {digest} for funding: {e}"
			)));
		}
	}
	// on the error paths above the staging directory is left for the file transfer handler's sweep
	let _ = fs::remove_dir_all(&staging_dir);

	if remote_rgb_assignments.len() != 1 {
		return Err(ChannelError::close(format!(
			"Unexpected number of RGB assignments: {}",
			remote_rgb_assignments.len()
		)));
	}
	let channel_rgb_amount = match remote_rgb_assignments[0] {
		Assignment::Fungible(amt) => amt,
		Assignment::NonFungible => 1,
		_ => unreachable!("unsupported schema"),
	};
	let push_amount = push_asset_amount.unwrap_or(0);
	let remote_rgb_amount = channel_rgb_amount.checked_sub(push_amount).ok_or_else(|| {
		ChannelError::close(format!(
			"push_asset_amount {push_amount} exceeds channel asset amount {channel_rgb_amount}"
		))
	})?;
	let rgb_info = RgbInfo {
		contract_id: consignment.contract_id(),
		schema: AssetSchema::from_schema_id(consignment.schema_id()).unwrap(),
		local_rgb_amount: push_amount,
		remote_rgb_amount,
		batch_transfer_idx: None,
		// only meaningful on the initiator side, which is the one that sends media
		counterparty_knows_asset: false,
	};
	let temporary_channel_id_str = temporary_channel_id.0.as_hex().to_string();
	write_rgb_channel_info(
		&get_rgb_channel_info_path(&temporary_channel_id_str, ldk_data_dir, true),
		&rgb_info,
	);
	write_rgb_channel_info(
		&get_rgb_channel_info_path(&temporary_channel_id_str, ldk_data_dir, false),
		&rgb_info,
	);

	Ok(())
}

pub(crate) fn set_counterparty_knows_asset(channel_id: &ChannelId, ldk_data_dir: &Path) {
	let channel_id = channel_id.0.as_hex().to_string();
	for pending in [true, false] {
		let info_file_path = get_rgb_channel_info_path(&channel_id, ldk_data_dir, pending);
		if !info_file_path.exists() {
			continue;
		}
		let mut rgb_info = parse_rgb_channel_info(&info_file_path);
		rgb_info.counterparty_knows_asset = true;
		write_rgb_channel_info(&info_file_path, &rgb_info);
	}
}

/// Update RGB channel amount
pub fn update_rgb_channel_amount(
	channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path,
	pending: bool,
) {
	let (mut rgb_info, info_file_path) = get_rgb_channel_info(channel_id, ldk_data_dir, pending);

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

/// Update pending RGB channel amount
pub(crate) fn update_rgb_channel_amount_pending(
	channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path,
) {
	update_rgb_channel_amount(
		&channel_id.0.as_hex().to_string(),
		rgb_offered_htlc,
		rgb_received_htlc,
		ldk_data_dir,
		true,
	)
}

/// Whether the payment is colored
pub(crate) fn is_payment_rgb(ldk_data_dir: &Path, payment_hash: &PaymentHash) -> bool {
	get_rgb_payment_info_path(payment_hash, ldk_data_dir, false).exists()
		|| get_rgb_payment_info_path(payment_hash, ldk_data_dir, true).exists()
}

/// Detect the contract ID of the payment and then filter hops based on contract ID and amount
pub(crate) fn filter_first_hops(
	ldk_data_dir: &Path, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>,
) -> (ContractId, u64) {
	let rgb_payment_info_path = get_rgb_payment_info_path(payment_hash, ldk_data_dir, false);
	let rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_path);
	let contract_id = rgb_payment_info.contract_id;
	let rgb_amount = rgb_payment_info.amount;
	first_hops.retain(|h| {
		let info_file_path = ldk_data_dir.join(h.channel_id.0.as_hex().to_string());
		if !info_file_path.exists() {
			return false;
		}
		let serialized_info = fs::read_to_string(info_file_path).expect("valid rgb info file");
		let rgb_info: RgbInfo =
			serde_json::from_str(&serialized_info).expect("valid rgb info file");
		rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
	});
	(contract_id, rgb_amount)
}
