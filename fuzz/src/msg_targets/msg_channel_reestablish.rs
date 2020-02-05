// This file is auto-generated by gen_target.sh based on msg_target_template.txt
// To modify it, modify msg_target_template.txt and run gen_target.sh instead.

use lightning::ln::msgs;

use msg_targets::utils::VecWriter;

#[inline]
pub fn do_test(data: &[u8]) {
	test_msg!(msgs::ChannelReestablish, data);
}

#[no_mangle]
pub extern "C" fn msg_channel_reestablish_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
