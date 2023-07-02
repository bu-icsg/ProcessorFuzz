#!/bin/bash

# Usage ./edit_inout.sh file_to_edit.v

fname=$1

sed -i 's/\<auto_tl_other_masters_out_a_bits_address\>/auto_tl_master_xing_out_a_bits_address/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_bits_corrupt\>/auto_tl_master_xing_out_a_bits_corrupt/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_bits_data\>/auto_tl_master_xing_out_a_bits_data/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_bits_mask\>/auto_tl_master_xing_out_a_bits_mask/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_bits_opcode\>/auto_tl_master_xing_out_a_bits_opcode/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_bits_param\>/auto_tl_master_xing_out_a_bits_param/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_bits_size\>/auto_tl_master_xing_out_a_bits_size/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_bits_source\>/auto_tl_master_xing_out_a_bits_source/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_ready\>/auto_tl_master_xing_out_a_ready/g' $fname
sed -i 's/\<auto_tl_other_masters_out_a_valid\>/auto_tl_master_xing_out_a_valid/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_address\>/auto_tl_master_xing_out_b_bits_address/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_corrupt\>/auto_tl_master_xing_out_b_bits_corrupt/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_data\>/auto_tl_master_xing_out_b_bits_data/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_mask\>/auto_tl_master_xing_out_b_bits_mask/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_opcode\>/auto_tl_master_xing_out_b_bits_opcode/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_param\>/auto_tl_master_xing_out_b_bits_param/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_size\>/auto_tl_master_xing_out_b_bits_size/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_bits_source\>/auto_tl_master_xing_out_b_bits_source/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_ready\>/auto_tl_master_xing_out_b_ready/g' $fname
sed -i 's/\<auto_tl_other_masters_out_b_valid\>/auto_tl_master_xing_out_b_valid/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_bits_address\>/auto_tl_master_xing_out_c_bits_address/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_bits_corrupt\>/auto_tl_master_xing_out_c_bits_corrupt/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_bits_data\>/auto_tl_master_xing_out_c_bits_data/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_bits_opcode\>/auto_tl_master_xing_out_c_bits_opcode/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_bits_param\>/auto_tl_master_xing_out_c_bits_param/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_bits_size\>/auto_tl_master_xing_out_c_bits_size/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_bits_source\>/auto_tl_master_xing_out_c_bits_source/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_ready\>/auto_tl_master_xing_out_c_ready/g' $fname
sed -i 's/\<auto_tl_other_masters_out_c_valid\>/auto_tl_master_xing_out_c_valid/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_corrupt\>/auto_tl_master_xing_out_d_bits_corrupt/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_data\>/auto_tl_master_xing_out_d_bits_data/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_denied\>/auto_tl_master_xing_out_d_bits_denied/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_opcode\>/auto_tl_master_xing_out_d_bits_opcode/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_param\>/auto_tl_master_xing_out_d_bits_param/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_sink\>/auto_tl_master_xing_out_d_bits_sink/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_size\>/auto_tl_master_xing_out_d_bits_size/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_bits_source\>/auto_tl_master_xing_out_d_bits_source/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_ready\>/auto_tl_master_xing_out_d_ready/g' $fname
sed -i 's/\<auto_tl_other_masters_out_d_valid\>/auto_tl_master_xing_out_d_valid/g' $fname
sed -i 's/\<auto_tl_other_masters_out_e_bits_sink\>/auto_tl_master_xing_out_e_bits_sink/g' $fname
sed -i 's/\<auto_tl_other_masters_out_e_ready\>/auto_tl_master_xing_out_e_ready/g' $fname
sed -i 's/\<auto_tl_other_masters_out_e_valid\>/auto_tl_master_xing_out_e_valid/g' $fname
sed -i 's/\<auto_int_local_in_0_0\>/auto_intsink_in_sync_0/g' $fname
sed -i 's/\<auto_int_local_in_1_0\>/auto_int_in_xing_in_0_sync_0/g' $fname
sed -i 's/\<auto_int_local_in_1_1\>/auto_int_in_xing_in_0_sync_1/g' $fname
sed -i 's/\<auto_int_local_in_2_0\>/auto_int_in_xing_in_1_sync_0/g' $fname
sed -i 's/\<auto_int_local_in_3_0\>/auto_int_in_xing_in_2_sync_0/g' $fname
sed -i 's/\<auto_reset_vector_in\>/constants_reset_vector/g' $fname
