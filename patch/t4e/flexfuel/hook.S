.section .text
.global hook_ign_advance_high_cam_base, hook_ign_advance_low_cam_base, hook_ign_advance_adj1, hook_inj_time_adj_cranking, hook_inj_efficiency, hook_inj_time_adj3, hook_injtip_in_adj1, hook_injtip_out_adj1

hook_ign_advance_high_cam_base:
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l
	addi	%r10, %r12, OFF_CAL_ethanol_ign_advance_high_cam_base
	lbz	%r11, OFF_CAL_ethanol_scale_2_low(%r12)
	lbz	%r12, OFF_CAL_ethanol_scale_2_high(%r12)
	bl	lookup_3D_uint8_interpolated_withblend
	ba	hook_ign_advance_high_cam_base_continue

hook_ign_advance_low_cam_base:
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l
	addi	%r10, %r12, OFF_CAL_ethanol_ign_advance_low_cam_base
	lbz	%r11, OFF_CAL_ethanol_scale_2_low(%r12)
	lbz	%r12, OFF_CAL_ethanol_scale_2_high(%r12)
	bl	lookup_3D_uint8_interpolated_withblend
	ba	hook_ign_advance_low_cam_base_continue

hook_ign_advance_adj1:
	lis	%r9, CAL_base_extra@ha
	addi	%r9, %r9, CAL_base_extra@l
	addi	%r7, %r9, OFF_CAL_ethanol_ign_advance_adj1
	lbz	%r8, OFF_CAL_ethanol_scale_1_low(%r9)
	lbz	%r9, OFF_CAL_ethanol_scale_1_high(%r9)
	bl	lookup_2D_uint8_interpolated_withblend
	ba	hook_ign_advance_adj1_continue

hook_inj_time_adj_cranking:
	lis	%r9, CAL_base_extra@ha
	addi	%r9, %r9, CAL_base_extra@l
	addi	%r7, %r9, OFF_CAL_ethanol_inj_time_adj_cranking
	lbz	%r8, OFF_CAL_ethanol_scale_1_low(%r9)
	lbz	%r9, OFF_CAL_ethanol_scale_1_high(%r9)
	bl	lookup_2D_uint8_interpolated_withblend
	ba	hook_inj_time_adj_cranking_continue

hook_inj_efficiency:
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l
	addi	%r10, %r12, OFF_CAL_ethanol_inj_efficiency
	lbz	%r11, OFF_CAL_ethanol_scale_1_low(%r12)
	lbz	%r12, OFF_CAL_ethanol_scale_1_high(%r12)
	bl	lookup_3D_uint8_interpolated_withblend
	ba	hook_inj_efficiency_continue

hook_inj_time_adj3:
	lis	%r12, CAL_base_extra@ha
	addi	%r12, %r12, CAL_base_extra@l
	addi	%r10, %r12, OFF_CAL_ethanol_inj_time_adj3
	lbz	%r11, OFF_CAL_ethanol_scale_1_low(%r12)
	lbz	%r12, OFF_CAL_ethanol_scale_1_high(%r12)
	bl	lookup_3D_uint8_interpolated_withblend
	ba	hook_inj_time_adj3_continue

hook_injtip_in_adj1:
	lis	%r9, CAL_base_extra@ha
	addi	%r9, %r9, CAL_base_extra@l
	addi	%r7, %r9, OFF_CAL_ethanol_injtip_in_adj1
	lbz	%r8, OFF_CAL_ethanol_scale_1_low(%r9)
	lbz	%r9, OFF_CAL_ethanol_scale_1_high(%r9)
	bl	lookup_2D_uint8_interpolated_withblend
	ba	hook_injtip_in_adj1_continue

hook_injtip_out_adj1:
	lis	%r9, CAL_base_extra@ha
	addi	%r9, %r9, CAL_base_extra@l
	addi	%r7, %r9, OFF_CAL_ethanol_injtip_out_adj1
	lbz	%r8, OFF_CAL_ethanol_scale_1_low(%r9)
	lbz	%r9, OFF_CAL_ethanol_scale_1_high(%r9)
	bl	lookup_2D_uint8_interpolated_withblend
	ba	hook_injtip_out_adj1_continue
