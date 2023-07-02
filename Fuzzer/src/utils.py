import os
import shutil
import psutil
import signal
import csv
from threading import Timer
import struct
import binascii
import math
from pathlib import Path
#from subprocess import STDOUT, check_output, check_call, Popen
import subprocess
import time
import sys

from ISASim.host import rvISAhost
from RTLSim.host import rvRTLhost

from src.preprocessor import rvPreProcessor
from src.signature_checker import sigChecker
from src.mutator import simInput, rvMutator
from src.multicore_manager import proc_state, procManager

ISA_TIME_LIMIT = 1

comb_t = []
comb_priv = []
comb_func = []
instrs = []

reg_map = {
'zero': 0,
'ra': 1,
'sp': 2,
'gp': 3,
'tp': 4,
't0': 5,
't1': 6,
't2': 7,
's0': 8,
'fp': 8,
's1': 9,
'a0': 10,
'a1': 11,
'a2': 12,
'a3': 13,
'a4': 14,
'a5': 15,
'a6': 16,
'a7': 17,
's2': 18,
's3': 19,
's4': 20,
's5': 21,
's6': 22,
's7': 23,
's8': 24,
's9': 25,
's10': 26,
's11': 27,
't3': 28,
't4': 29,
't5': 30,
't6': 31
}
freg_map = {
'ft0': 0,
'ft1': 1,
'ft2': 2,
'ft3': 3,
'ft4': 4,
'ft5': 5,
'ft6': 6,
'ft7': 7,
'fs0': 8,
'fs1': 9,
'fa0': 10,
'fa1': 11,
'fa2': 12,
'fa3': 13,
'fa4': 14,
'fa5': 15,
'fa6': 16,
'fa7': 17,
'fs2': 18,
'fs3': 19,
'fs4': 20,
'fs5': 21,
'fs6': 22,
'fs7': 23,
'fs8': 24,
'fs9': 25,
'fs10': 26,
'fs11': 27,
'ft8': 28,
'ft9': 29,
'ft10': 30,
'ft11': 31
}

f_instr = ['flw', 'fsw', 'fmadd.s', 'fmsub.s', 'fnmsub.s', 'fnmadd.s', 'fadd.s', 'fsub.s', 'fmul.s', 'fdiv.s', 'fsqrt.s', 'fsgnj.s', 'fsgnjn.s', 'fsgnjx.s', 'fmin.s', 'fmax.s', 'fcvt.w.s', 'fcvt.wu.s', 'fmv.x.w', 'feq.s', 'flt.s', 'fle.s', 'fclass.s', 'fcvt.s.w', 'fcvt.s.wu', 'fmv.w.x', 'fcvt.l.s', 'fcvt.lu.s', 'fcvt.s.l', 'fcvt.s.lu']

d_instr = ['fld', 'fsd', 'fmadd.d', 'fmsub.d', 'fnmsub.d', 'fnmadd.d', 'fadd.d', 'fsub.d', 'fmul.d', 'fdiv.d', 'fsqrt.d', 'fsgnj.d', 'fsgnjn.d', 'fsgnjx.d', 'fmin.d', 'fmax.d', 'fcvt.s.d', 'fcvt.d.s', 'feq.d', 'flt.d', 'fle.d', 'fclass.d', 'fcvt.w.d', 'fcvt.wu.d', 'fcvt.d.w', 'fcvt.d.wu', 'fcvt.l.d', 'fcvt.lu.d', 'fmv.x.d', 'fcvt.d.l', 'fcvt.d.lu', 'fmv.d.x']

#ignore_list = ['mret', 'csrw    mepc', 'csrwi   frm', 'csrwi   mscratch']
ignore_list = ['csrw    minstret', 'mret', 'sret', 'ebreak', 'csrw    mepc', 'csrwi   mstatus', 'csrs    mstatus', 'csrs    medeleg', 'csrw    medeleg', 'csrw    mstatus', 'ecall', 'csrr    sp, mtval']
#ignore_list = []
def get_FS(mstatus):
    return ((int(mstatus, 16)>>13)&3)
def trace_compare(isa_csv, rtl_log, toplevel, strategy=''):

    rtl_f = open(rtl_log, 'r')
    rtl_lines = rtl_f.readlines()
    rtl_f.close() 
    rtl_trace_idx = 1 # skip the first line with headers
    rtl_trace_len = len(rtl_lines)
    rtl_pc_start = ''   
    mismatch = False
    not_found = False
    isa_idx_offset = 0
    delayed_result_not_found = False
    return_val = 0
    init_value = True
    rtl_trace_start = 0
    hdr = ''
    isa_m_str = ''
    rtl_m_str = ''
    mode_isa = ''
    lr_addr = 0
    sc_addr = 0
    wdata_p = 0
    lrsc_exception = False
    exception = False
    initial = True
    instr_str_p = ''
    for x in range(10):
        if 'DELAYED' in rtl_lines[x]: continue
        if toplevel=='BoomTile':
            pc_rtl = rtl_lines[x].split()[2][10:]
        else:
            pc_rtl = rtl_lines[x].split()[2][4:]
        if pc_rtl=='80000000':
        #if rtl_lines[x].split()[2][10:]=='80000000':
            rtl_trace_start = x
            break
    isa_f = open(isa_csv, 'r') 
    try:
    #if True:
        isa_csv = csv.reader(isa_f)
        next(isa_csv, None)
        isa_csv = list(isa_csv)
        if rtl_trace_len == 1: #only the header is available
            print("ERROR: Empty RTL trace file - ",rtl_log)
            isa_f.close()
            return -1
         
        for j in range(len(isa_csv[isa_idx_offset:])): # skip the first line with headers
            line = isa_csv[isa_idx_offset+j]
            #print(line)
            #if ('ecall') in line:
            #    print("[COMPARISON PASSED]")
            #    isa_f.close()
            #    break
            #pc,instr,gpr,csr,binary,mode,instr_str,operand,pad
            #print(line)
            pc_isa = line[0][8:]
            instr_isa = line[4]
            line[2] = line[2].split(';')[0]
            if len(line[2].split(':')) < 2:# for no write back value, set it to zeros
                wdata_isa = '0000000000000000'
            else:
                wdata_isa = line[2].split(':')[1]
            pmode_isa = mode_isa
            mode_isa = line[5]
            instr_str_isa = line[6]
            mstatus_isa = line[9].zfill(16)
            frm_isa = line[10].zfill(1)
            fflags_isa = line[11].zfill(2)
            mcause_isa = line[12].zfill(2)
            scause_isa = line[13].zfill(2)
            medeleg_isa = line[14].zfill(16)
            mcounteren_isa = line[15].zfill(8)
            scounteren_isa = line[16].zfill(8)
            mcause_isa = mcause_isa[-1]
            scause_isa = scause_isa[-1]
            if mode_isa == '':
                mode_isa = pmode_isa
            #dcsr_isa = line[11].zfill(8)
            while "DELAYED" in rtl_lines[rtl_trace_start+j]: #skip all delayed values
                rtl_trace_start = rtl_trace_start + 1
            if instr_str_isa.split()[0] in ['lr.w', 'lr.d']:
                lrsc_exception = False
                lr_addr = int(wdata_p, 16)
            if "EXCEPTION" in rtl_lines[rtl_trace_start+j]:
                exception = True
                lrsc_exception = True
                if toplevel=='RocketTile':
                    if rtl_lines[rtl_trace_start+j].split()[2][4:]!=pc_isa:
                        rtl_trace_start = rtl_trace_start + 1
                #if rtl_lines[rtl_trace_start+j].split()[2][10:]!=pc_isa: #Only for BOOM for now
                #    rtl_trace_start = rtl_trace_start + 1
            else:
                exception = False

            i = rtl_trace_start+j
            rtl_line = rtl_lines[i].split()
            if toplevel=='BoomTile':
                pc_rtl = rtl_line[2][10:]
            elif toplevel=='RocketTile':
                pc_rtl = rtl_line[2][4:]
            #print("PC",pc_rtl, toplevel)
            #pc_rtl = rtl_lines[rtl_trace_start+j].split()[2][10:]
            #print("PC ISA: {}, RTL: {}".format(pc_isa, pc_rtl))
            instr_rtl = rtl_line[3][2:]
            wdata_rtl = rtl_line[4][2:]
            mode_rtl = rtl_line[1]
            if toplevel=='RocketTile':
                mstatus_rtl = rtl_line[5]
            #if toplevel=='BoomTile':
                frm_rtl = frm_isa
                fflags_rtl = fflags_isa
                mcause_rtl = rtl_line[6][-1]
                scause_rtl = rtl_line[7][-1]
                medeleg_rtl = rtl_line[8]
                mcounteren_rtl = rtl_line[9]
                scounteren_rtl = rtl_line[10]
            else:
                mstatus_rtl = rtl_line[5]
                frm_rtl = rtl_line[6]
                fflags_rtl = rtl_line[7].zfill(2)
                mcause_rtl = rtl_line[8][-1]
                scause_rtl = rtl_line[9][-1]
                medeleg_rtl = rtl_line[10]
                mcounteren_rtl = rtl_line[11]
                scounteren_rtl = rtl_line[12]
                #dcsr_rtl = rtl_line[6]
            if pc_isa!=pc_rtl:
                print("PC MISMATCH: ISA - {}, RTL - {}".format(pc_isa,pc_rtl))
                isa_f.close()
                return_val = -1
                if scause_rtl=='f' and mcause_isa=='6':
                    print("Bug 14: Rocket exception priority is incorrect when store page fault and store misaligned address exceptions are generated")
                break

            if instr_str_isa.split()[0] in ['j', 'ret']:
                wdata_rtl = '0000000000000000'
            if instr_str_isa.split()[0] in ['csrw', 'csrwi']:
                wdata_isa = '0000000000000000'
                wdata_rtl = '0000000000000000'
                #continue

            if 'csrr    sp, mip' in instr_str_isa.rstrip() and wdata_isa=='0000000000000080' and wdata_rtl=='0000000000000000':# Spike set mip to 0x80, we will skip this to match RTL
                wdata_isa = wdata_rtl
            if instr_str_isa.rstrip() in ['jal     0x10', 'auipc   t6, 0x20'] and mstatus_isa == '8000000a00006000' and mstatus_rtl == '8000000a00007800':
                mstatus_isa = mstatus_rtl
            if exception and instr_isa == '00000000':
                print("Bug 11: BOOM gives instr access fault on 0x000000 instr but spike gives illegal instr")
            if 'deadbeef' in wdata_rtl:
                reg = instr_str_isa.split()[1][:-1]
                if reg[0] == 'f':
                    isa_wb_reg = 'f'+str(freg_map[reg])
                else:
                    isa_wb_reg = 'r'+str(reg_map[reg])
                #print(isa_wb_reg)
                for k in range(i+1, rtl_trace_len):
                    if 'DELAYED' in rtl_lines[k]:
                        #print(rtl_lines[k].split('=')[0].split()[1])
                        if (rtl_lines[k].split('=')[0].split()[1]==isa_wb_reg):
                            wdata_rtl= rtl_lines[k].split('=')[1].split()[0].rstrip()
                            #print("DELAYED result: ",wdata_rtl, rtl_lines[k].split('=')[0].split()[1])
                            break
                    if k == rtl_trace_len-1: 
                        delayed_result_not_found = True
                        break
            if ( instr_isa!=instr_rtl or wdata_isa!=wdata_rtl or mode_isa!=mode_rtl or mstatus_isa!=mstatus_rtl or fflags_isa!=fflags_rtl or mcause_rtl!= mcause_isa or scause_rtl!=scause_isa or medeleg_rtl!=medeleg_isa or mcounteren_rtl!=mcounteren_isa or scounteren_rtl!=scounteren_isa):
                mismatch = True
                #if mstatus_isa=='0000000a00000000' and init_value: # Skip init value check
                #    mismatch = False
                #else:
                #    init_value = False
                #print(instr_rtl)
                if instr_str_isa.split()[0] in ['sc.w', 'sc.d']:
                     sc_addr = int(wdata_p, 16)
                     if int(wdata_isa, 16) == 1 and int(wdata_rtl, 16) == 0:
                          print("LRSC addr gap = ", abs(lr_addr-sc_addr))
                          if lrsc_exception:
                               print("Bug 7: Misaligned lr instruction on a cached line set the reservation")
                     lrsc_exception = False
                if get_FS(mstatus_isa) != get_FS(mstatus_rtl) and instr_str_p.split()[0] in ['csrw', 'csrwi']:
                    if instr_str_p.split()[1].split(',')[0].strip() in ['mstatus', 'sstatus']:
                        print("Bug 9: FS is not set to dirty when mstatus is written")
                     
                if int(fflags_isa,16) == int(fflags_rtl, 16) + 16:
                     print("Bug 6: Invalid operation flag is not set after invalid fdiv instruction")
                if mismatch and instr_str_isa.split()[0][0]=='f':
                     if (int(instr_isa,16)>>12)&7 in [5,6]:
                         print ("Bug 2: Invalid rm field does not raise exception")
                     if (int(instr_isa,16)>>12)&7 in [7] and frm_isa=='7':
                         print ("Bug 4: When frm is set DYN, floating point instruction with DYN rm field should raise exception")
                if 'EXCEPTION' in rtl_line: #skipping privilege mismatch on exception
                     mismatch = False
                if mismatch and wdata_isa!=wdata_rtl and instr_str_isa.split()[0] in f_instr + d_instr:
                    #if wdata_isa[:8] == 'ffffffff' and wdata_rtl[:8] == '00000000' and wdata_isa[8:] == wdata_rtl[8:]:
                    if (int(wdata_isa, 16) == int(wdata_rtl, 16) + 1) or (int(wdata_isa, 16) == int(wdata_rtl, 16) - 1):
                        print ("Bug 5: Floating point rounding mode not working correctly")
                    #    mismatch = False
                    #if toplevel=='BoomTile':
                    if  instr_str_isa.split()[0] in f_instr: #consider as float
                        wdata_isa_f = struct.unpack('!f', binascii.unhexlify(wdata_isa[8:]))[0] #float.fromhex(wdata_isa)
                        wdata_rtl_f = struct.unpack('!f', binascii.unhexlify(wdata_rtl[8:]))[0] #float.fromhex(wdata_rtl)
                    else: #consider as double
                        wdata_isa_f = struct.unpack('>d', binascii.unhexlify(wdata_isa))[0] #float.fromhex(wdata_isa)
                        wdata_rtl_f = struct.unpack('>d', binascii.unhexlify(wdata_rtl))[0] #float.fromhex(wdata_rtl)
                    if (wdata_isa_f==wdata_rtl_f):#< 1e-09:
                        mismatch = False
                    elif math.isnan(wdata_isa_f) and math.isnan(wdata_rtl_f): #to handle nan
                        print("Both NaN")
                        mismatch = False
                    else:
                        print("Comparison failed          : ",wdata_isa_f, wdata_rtl_f)

                if instr_str_isa.split(',')[0] in ignore_list:
                    mismatch = False
                elif instr_str_isa == 'csrr    sp, mtval': 
                    mismatch = False
                if mismatch and len(instr_str_isa.split(','))==3:
                    if instr_str_isa.split(',')[1].lstrip() in ['fcsr', 'medeleg', 'mstatus', 'mcause', 'fflags', 'scause', 'sstatus']:
                        mismatch = False
                if 'zero' in instr_str_isa:
                    if instr_str_isa.split()[1].split(',')[0]=='zero':
                        mismatch = False
                #if mismatch and (mode_isa!=mode_rtl or mstatus_isa!=mstatus_rtl or fflags_isa!=fflags_rtl):
                #    print("INTERESTING")
                if mismatch:
                    hdr = 'MISMATCH: {}\n\tPC\t\tINSTR\t\tMODE\tWDATA\t\t'.format(instr_str_isa)
                    isa_m_str = 'ISA:\t{}\t{}\t{}\t{}\t'.format(pc_isa,instr_isa,mode_isa,wdata_isa)
                    rtl_m_str = 'RTL:\t{}\t{}\t{}\t{}\t'.format(pc_rtl,instr_rtl,mode_rtl,wdata_rtl)
                    if mstatus_isa!=mstatus_rtl:
                        hdr = hdr + '\tMSTATUS'
                        isa_m_str = isa_m_str + '{}\t'.format(mstatus_isa)
                        rtl_m_str = rtl_m_str + '{}\t'.format(mstatus_rtl)
                    if mcause_isa!=mcause_rtl:
                        hdr = hdr + '\tmcause'
                        isa_m_str = isa_m_str + '{}\t'.format(mcause_isa)
                        rtl_m_str = rtl_m_str + '{}\t'.format(mcause_rtl)
                    if scause_isa!=scause_rtl:
                        hdr = hdr + '\tscause'
                        isa_m_str = isa_m_str + '{}\t'.format(scause_isa)
                        rtl_m_str = rtl_m_str + '{}\t'.format(scause_rtl)
                    if medeleg_isa!=medeleg_rtl:
                        hdr = hdr + '\tmedeleg'
                        isa_m_str = isa_m_str + '{}\t'.format(medeleg_isa)
                        rtl_m_str = rtl_m_str + '{}\t'.format(medeleg_rtl)
                    if fflags_isa!=fflags_rtl:
                        hdr = hdr + '\tfflags'
                        isa_m_str = isa_m_str + '{}\t'.format(fflags_isa)
                        rtl_m_str = rtl_m_str + '{}\t'.format(fflags_rtl)

                        #if mismatch and strategy=='M5':
                        #    if instr_rtl=='00000000': #PMP cache issue
                        #        return_val = -2
                    #break
                if i == rtl_trace_len-1: #search reached and of trace, instruction not found in RTL
                    not_found = True
                    #print(pc_isa, instr_isa, wdata_isa, mode_isa)
                    #print(pc_rtl, instr_rtl, wdata_rtl, mode_rtl)
                    #break
            if delayed_result_not_found:
                print("DELAYED WB RESULT NOT FOUND: {}\n\t\t\tPC\t\t\tINSTR\t\tMODE\tWDATA \nISA:\t\t{}\t{}\t{}\t\t{}\n".format(instr_str_isa,pc_isa,instr_isa,mode_isa,wdata_isa))
                delayed_result_not_found = False
                #isa_f.close()
                break
            if mismatch:
                #print("MISMATCH: {}\n\t\t\tPC\t\t\tINSTR\t\tMODE\tWDATA \nISA:\t\t{}\t{}\t{}\t\t{}\t\t{}\t\t{}\nRTL:\t\t{}\t{}\t{}\t\t{}\t\t{}\t\t{}".format(instr_str_isa,pc_isa,instr_isa,mode_isa,wdata_isa,mstatus_isa, fflags_isa, pc_rtl,instr_rtl,mode_rtl,wdata_rtl,mstatus_rtl, fflags_rtl))
                if initial:
                    print(hdr)
                    print(isa_m_str)
                    print(rtl_m_str)
                    initial = False
                #mismatch = False
                return_val = -1
                #break
            if not_found:
                print("INSTRUCTION NOT FOUND: {}\n\t\t\tPC\t\t\tINSTR\t\tMODE\tWDATA \nISA:\t\t{}\t{}\t{}\t\t{}\n".format(instr_str_isa,pc_isa,instr_isa,mode_isa,wdata_isa))
                isa_f.close()
                break
            if return_val==-2:
                isa_f.close()
                break
            #if j==len(isa_csv[isa_idx_offset:])-1 and not mismatch and initial:
            #    print("[COMPARISON PASSED]")
            wdata_p = wdata_isa 
            instr_str_p = instr_str_isa
            #k = k + 1
    except:
        print("ERROR: Trace comparison did not complete")
    isa_f.close()
    return return_val

def extract_transitions(i_file, out, it, ALL_CSR, FP_CSR):
	fd = open(i_file, "r")
	fdb = open(out+"/transition.db","a")	
	lines = fd.readlines()
	fd.close()
	init = True
	count = 0
	duplic = []
	transitions = []
	csr_names = ['mstatus', 'mcause', 'scause', 'fflags']
	csr = ''
	j = 0
	skip = False
	for l in lines:
		if '[' not in l:
			continue
		count = count + 1
		vals = l.split('[')[1].split(']')[0]
		instr = l.split('[')[1].split(']')[1].rstrip()
		vals = vals.split(',')
		mstatus = vals[0]
		frm = vals[1]
		fflags = vals[2]
		mcause = vals[3]
		scause = vals[4]
		medeleg =  vals[5] #Set this to zero for some experiments vals[5]
		mcounteren = vals[6]
		scounteren = vals[7]
		#dcsr = vals[8]
		if ALL_CSR:
			dcsr = vals[8]
			misa = vals[9]
			mhartid = vals[10]
			mip = vals[11]
			mie = vals[12]
			mideleg = vals[13]
			mepc = vals[14]
			mtval = vals[15]
			mtvec = vals[16]
			mscratch = vals[17]
			sstatus = vals[18]
			sip = vals[19]
			sie = vals[20]
			sepc = vals[21]
			stval = vals[22]
			sscratch = vals[23]
			satp = vals[24]
			stvec = vals[25]
			dpc = vals[26]
			tselect = vals[27]
			tdata1 = vals[28]
			tdata2 = vals[29]
			tdata3 = vals[30]
			mcountinhibit = vals[31]
			cycle = vals[32]
			instret = vals[33]
			mhpmevent = vals[34]
			mhpmcounter = vals[35]
			vstart = vals[36]
			vxsat = vals[37]
			vxrm = vals[38]
			pmpcfg = vals[39]
			pmpaddr = vals[40]
		
		pc = l.split()[2]

		if init:
			init = False
		elif ALL_CSR:
			if (mstatus_p != mstatus) or (frm_p != frm) or (fflags_p != fflags) or (mcause_p != mcause) or (scause_p != scause) or (medeleg_p != medeleg) or (mcounteren_p != mcounteren) or (scounteren_p != scounteren) or (dcsr_p != dcsr) or (misa_p != misa) or (mhartid_p != mhartid) or (mip_p != mip) or (mie_p != mie) or (mideleg_p != mideleg) or (mepc_p != mepc) or (mtval_p != mtval) or (mtvec_p != mtvec) or (mscratch_p != mscratch) or (sstatus_p != sstatus) or (sip_p != sip) or (sie_p != sie) or (sepc_p != sepc) or (stval_p != stval) or (sscratch_p != sscratch) or (satp_p != satp) or (stvec_p != stvec) or (dpc_p != dpc) or (tselect_p != tselect) or (tdata1_p != tdata1) or (tdata2_p != tdata2) or (tdata3_p != tdata3) or (mcountinhibit_p != mcountinhibit) or (cycle_p != cycle) or (instret_p != instret) or (mhpmevent_p != mhpmevent) or (mhpmcounter_p != mhpmcounter) or (vstart_p != vstart) or (vxsat_p != vxsat) or (vxrm_p != vxrm) or (pmpcfg_p != pmpcfg) or (pmpaddr_p != pmpaddr):
				comp = mstatus+frm+fflags+mcause+scause+medeleg+mcounteren+scounteren+dcsr+misa+mhartid+mip+mie+mideleg+mepc+mtval+mtvec+mscratch+sstatus+sip+sie+sepc+stval+sscratch+satp+stvec+dpc+tselect+tdata1+tdata2+tdata3+mcountinhibit+cycle+instret+mhpmevent+mhpmcounter+vstart+vxsat+vxrm+pmpcfg+pmpaddr
				comp_p = mstatus_p+frm_p+fflags_p+mcause_p+scause_p+medeleg_p+mcounteren_p+scounteren_p+dcsr_p+misa_p+mhartid_p+mip_p+mie_p+mideleg_p+mepc_p+mtval_p+mtvec_p+mscratch_p+sstatus_p+sip_p+sie_p+sepc_p+stval_p+sscratch_p+satp_p+stvec_p+dpc_p+tselect_p+tdata1_p+tdata2_p+tdata3_p+mcountinhibit_p+cycle_p+instret_p+mhpmevent_p+mhpmcounter_p+vstart_p+vxsat_p+vxrm_p+pmpcfg_p+pmpaddr_p
				instr_t = instr_p.split()[0].strip()
				if (instr_t, comp_p, comp) not in comb_t:
					comb_t.append((instr_t, comp_p, comp))
					j += 1
		elif (mstatus_p != mstatus) or (frm_p != frm) or (fflags_p != fflags) or (mcause_p != mcause) or (scause_p != scause) or (medeleg_p != medeleg) or (mcounteren_p != mcounteren) or (scounteren_p != scounteren): #or (dcsr_p != dcsr):
			t = (pc_p + '\t' + mstatus_p +','+frm_p+','+fflags_p+','+mcause_p+','+scause_p+','+medeleg_p+','+mcounteren_p+','+scounteren_p+' '+instr_p, pc + '\t' + mstatus +','+frm+','+fflags+','+mcause+','+scause+','+medeleg+','+mcounteren+','+scounteren+' '+instr)
			comb = mstatus+frm+fflags+mcause+scause+medeleg+mcounteren+scounteren
			comb_p = mstatus_p+frm_p+fflags_p+mcause_p+scause_p+medeleg_p+mcounteren_p+scounteren_p
			comb_pr   = mstatus+mcause+scause+medeleg+mcounteren+scounteren
			comb_pr_p = mstatus_p+mcause_p+scause_p+medeleg_p+mcounteren_p+scounteren_p
			comb_f   = str((int(mstatus,16)>>13) & 3) +frm+fflags
			comb_f_p = str((int(mstatus_p,16)>>13) & 3) +frm_p+fflags_p
			instr_t = instr_p.split()[0].strip()
			csr = ''
			skip = False
			#instr = instr_p.split()[0].strip()
			if 'csrr' in instr_p: #Ex: csrrsi  a2, frm, 25
				#print(instr_p)
				instr_t += ' ' + instr_p.split(',')[1].strip() #Ex: csrrsi frm
				csr = instr_p.split(',')[1].strip()
			elif instr_t in ['csrw', 'csrs', 'csrc', 'csrwi', 'csrsi', 'csrci']:
				instr_t = ' '.join(instr_p.split(',')[0].split())
				csr = instr_p.split(',')[0].split()[1]
			if csr=='sstatus': csr = 'mstatus' #Treat mstatus same as sstatus
			if csr in csr_names:
				csr_n = []
				csr_l0 = [mstatus, mcause, scause, fflags]
				csr_l1 = [mstatus_p, mcause_p, scause_p, fflags_p]
				csr_l = []

				for i in range(len(csr_l0)):
					csr_n.append(csr_names[i]==csr) 
					csr_l.append(csr_l0[i] != csr_l1[i])
				#print(instr_p, csr_n, csr_l, file=fdb)
				if sum(csr_l)==1 and csr_l==csr_n: 
					#Criteria 2 - Skiiping the scenario of writing to a CSR and changing only that CSR
					skip = True
			priv_trns = False
			func_trns = False
			#if (instr_t, comb_p, comb) not in comb_t:
			#	comb_t.append((instr_t, comb_p, comb))
			#	transitions.append(t)
			if not skip:
				# Privileged CSR transition check - only considered when FP_CSR is not set
				if (not FP_CSR) and (instr_t, comb_pr_p, comb_pr) not in comb_priv and comb_pr_p!=comb_pr:
					comb_priv.append((instr_t, comb_pr_p, comb_pr))
					priv_trns = True
					print("PRIVILEGE",instr_t,file=fdb)
					print(comb_pr_p,file=fdb)
					print(comb_pr,file=fdb)
					j += 1

				# FP CSR transition check
				if (instr_t, comb_f_p, comb_f) not in comb_func and comb_f_p!=comb_f:
					comb_func.append((instr_t, comb_f_p, comb_f))
					func_trns = True
					print("FLOAT",instr_t,file=fdb)
					print(comb_f_p,file=fdb)
					print(comb_f,file=fdb)
					j += 1

				if priv_trns or func_trns:
					comb_t.append((instr_t, comb_p, comb))
					transitions.append(t)

			#j = j + 1
		#	mstatus_p = mstatus
		#	frm_p = frm
		#	fflags_p = fflags
		#	mcause_p = mcause
		#	instr_p = instr
	
		mstatus_p = mstatus
		frm_p = frm
		fflags_p = fflags
		mcause_p = mcause
		scause_p = scause
		medeleg_p = medeleg
		mcounteren_p = mcounteren
		scounteren_p = scounteren
		#dcsr_p = dcsr
		instr_p = instr
		pc_p = pc
		if ALL_CSR:
			dcsr_p = dcsr
			misa_p = misa
			mhartid_p = mhartid
			mip_p = mip
			mie_p = mie
			mideleg_p = mideleg
			mepc_p = mepc
			mtval_p = mtval
			mtvec_p = mtvec
			mscratch_p = mscratch
			sstatus_p = sstatus
			sip_p = sip
			sie_p = sie
			sepc_p = sepc
			stval_p = stval
			sscratch_p = sscratch
			satp_p = satp
			stvec_p = stvec
			dpc_p = dpc
			tselect_p = tselect
			tdata1_p = tdata1
			tdata2_p = tdata2
			tdata3_p = tdata3
			mcountinhibit_p = mcountinhibit
			cycle_p = cycle
			instret_p = instret
			mhpmevent_p = mhpmevent
			mhpmcounter_p = mhpmcounter
			vstart_p = vstart
			vxsat_p = vxsat
			vxrm_p = vxrm
			pmpcfg_p = pmpcfg
			pmpaddr_p = pmpaddr
	
	#j = 0
	#print(duplic)
	print("test ",it, file=fdb)
	#for p,c in transitions:
	#	#if not duplic[j]:
	#	print("###########################",file=fdb)
	#	print(p, file=fdb)
	#	print(c, file=fdb)
	#	j = j + 1
	print("Number of transitions : ",j, file=fdb)
	print("Instruction count     : ",count, file=fdb)
	fdb.close()
	return j
	#print(comb_t)

def bp_timeout(proc):
    proc.kill
    print("BP run timeout")

def check_mismatch_BP(error_list,elf_file):
    print("More analysis")

    print(''.join(map(str, error_list))) 
   # print(elf_file)
    emu_pc = int('0x' + error_list[1].split(' ')[3][:-1], 16)
    emu_pc_str = error_list[1].split(' ')[3][12:-1] + ":"
    dut_pc = int('0x' + error_list[1].split(' ')[6][:-1], 16)
    dut_pc_str =  error_list[1].split(' ')[6][12:-1] + ":"
    print(dut_pc_str)
    emu_inst = int('0x' + error_list[2].split(' ')[3][:-1], 16)
    n = 7
    bits = 1 << n
    opcode=emu_inst & (bits - 1) # keeps opcode
    is_FP_opcode = (opcode == 0b1001111) or (opcode == 0b1000011) or (opcode == 0b1010011) or (opcode == 0b1000111) or (opcode == 0b1001011)
    emu_satp = int('0x' + error_list[10].split(' ')[3][:-1],16)
    fname = os.environ['PWD'] + "/" + "dump.txt"
    f = open(fname, "w")
    output = None
    output_dut = None
    try:
        ret=subprocess.run(
          ["riscv64-unknown-elf-objdump", "-d", elf_file], stdout=f)
        print(emu_pc_str)
        output=subprocess.check_output(["grep", emu_pc_str,fname])
        print(str(output))
        output_dut=subprocess.check_output(["grep", dut_pc_str,fname])
        print(str(output_dut))
    except:
        print("No file to dump?")
    f.close()    
    
    contains_fflags=False
    contains_xepc = False
    contains_hartid = False
    contains_div_rem = False
    contains_xval = False
    if emu_pc == dut_pc: 
        if "fflags" in str(output) or "frm" in str(output):
            print("Found fflags or frm!")
            contains_fflags = True
        elif "sepc" in str(output) or "mepc" in str(output):
            print("Found sepc or mepc")
            contains_xepc = True
        elif "zero" in str(output) and ("div" in str(output) or "rem" in str(output)): 
            print("Found rem or div")
            contains_div_rem = True
        elif "stval" in str(output) or "mtval" in str(output):
            print("Found stval/mtval")
            contains_xval = True
    else: 
        if "mhartid" in str(output_dut):
            contains_hartid = True
            
    emu_mstatus = int('0x' + error_list[5].split(' ')[3][:-1], 16)
    dut_mstatus = int('0x' + error_list[5].split(' ')[6][:-1], 16)
    
    emu_FS = (emu_mstatus >> 13) & 3
    dut_FS = (dut_mstatus >> 13) & 3
    
    emu_mcause = int('0x' + error_list[3].split(' ')[3][:-1], 16)
    emu_scause = int('0x' + error_list[7].split(' ')[3][:-1], 16)

    emu_wdata = int('0x' + error_list[4].split(' ')[3][:-1], 16)
    dut_wdata = int('0x' + error_list[4].split(' ')[6][:-1], 16)
    
    emu_prev_priv = int(error_list[8].split(' ')[3][:-1])
    paddr = int('0x' + error_list[9].split(' ')[2][:-1], 16)
    try:
        dut_pending_exception = int('0x' + error_list[6].split(' ')[4], 16)
    except:
        print("No pending exception")
        dut_pending_exception = -1
    #print(dut_pending_exception)
    match = True
    if emu_prev_priv == 2:
        print("Hypervisor mode not supported, ignore")
    elif emu_pc != dut_pc:
        print("PC mismatch between DUT and EMU")
        if emu_mcause == 4 or emu_scause == 4: 
            print("Load misaligned, ignore")
        elif emu_mcause == 6 or emu_scause == 4:
            print("Store misaligned, ignore")
        elif dut_pending_exception == 7 and emu_mcause == 0:
            print("Bug 2: Store access fault in BP but not in dromajo") #todo:verify
        elif dut_pending_exception == 5 and emu_mcause == 0:
            print("Bug 2: Load access fault in BP but not in dromajo") #todo:verify
        elif dut_pending_exception == 1 and emu_mcause == 0:
            print("Bug 2: Instruction access fault in BP but not in dromajo") #todo:verify
        elif contains_hartid:
            print("Bug 6: Hartid is readonly bug!")
            match = False
        elif emu_satp != 0x8000000000080003:
            print("Mismatch due to satp is different?")
            print(hex(emu_satp)) 
            match = False
        else:
            print("Something else due to PC mismatch happened, Legit bug?")
            match = False
    else:
        if paddr <= 0x1000: #todo: probably useless after dromajo fix
            print("Physical address: " + hex(paddr) + " < 0x1000, ignore.")
        elif emu_inst == 0x34202173 and ((emu_wdata == 4 and dut_wdata == 5) or (emu_wdata == 6 and dut_wdata == 0xf) ):
            print("BP threw: " +  str(dut_wdata) + " Dromajo threw: " + str(emu_wdata)) 
        elif is_FP_opcode and emu_wdata!=dut_wdata:
            print("Bug 1: FP NaN")
        elif contains_div_rem and emu_wdata!=dut_wdata:
            print("Bug 7: Divison by 0 bug")
            match = False
        elif emu_FS == 0 and dut_FS == 3:
            print("Bug 4: FS field set to dirty!")
            match = False
        elif contains_xepc and emu_wdata!=dut_wdata:
            print("Bug 5: sepc or mepc LSB differs!")
            match = False
        elif contains_fflags:
            print("Bug 3: FFlags hazard bug!")
            match = False
        elif contains_xval and emu_wdata!=dut_wdata:
            print("Bug 8: stval/mtval mismatch")
            match = False
        elif emu_satp != 0x8000000000080003:
            print("Mismatch due to satp is different?")
            print(emu_satp) 
            match = False
        else:
            print("Legit bug?")
            match = False
    
    return match

def bp_run_test(BP_ROOT, test, it):
    out_env = os.environ['OUT']
    #Is this the first time?
    path = BP_ROOT+'/sdk/prog/{}'.format(out_env)
    print(path)
    isExist = os.path.isdir(path) #is batchX created before?
    if not isExist:
        Path(BP_ROOT+'/sdk/prog/{}/'.format(out_env)).mkdir(parents=True, exist_ok=True)    
        Path(BP_ROOT+'/rtl/logs/{}/'.format(out_env)).mkdir(parents=True, exist_ok=True)
        Path(BP_ROOT+'/rtl/covmap/{}/'.format(out_env)).mkdir(parents=True, exist_ok=True)
    print(test, it)
    elf_file = BP_ROOT + '/sdk/prog/{}/test_{}.riscv'.format(out_env,it)
    shutil.copyfile(test, elf_file)
    cwd = os.getcwd()
    print("HIIIII")
    print(test)
    os.chdir(BP_ROOT + '/rtl')
    args = ['make', '-C', 'bp_top/syn', 'build.sc', 'sim.sc', 'COSIM_P=1','CMT_TRACE_P=1' , 'SUITE={}'.format(out_env), 'PROG=test_{}'.format(it), 'TAG={}'.format(out_env)]#, '|', 'grep', '-e', 'error', '-e', 'CRTLCOV']
    fd = open('logs/{}/run.{}.log'.format(out_env,it), 'w')

    if isExist:
        tout = 30
        print("Exists")
    else : #for first time give more time since it builds stuff
        tout = 320 
    is_timeout = False
    try:
        print("Start")
        p = subprocess.Popen(args, stdout=fd, stderr=fd, start_new_session=True)
        p.wait(timeout=tout)
        stdout, stderr = p.communicate()
    except subprocess.TimeoutExpired:
        is_timeout = True
        fd.flush()
        fd.close()
        print(f'Timeout {tout}s expired', file=sys.stderr)
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        p.wait()
    
    print(sys.exc_info()[0])
    if is_timeout:
        os.chdir(cwd)
        print("RTL run timeout/failed")
        return(-1, 0, True) #Fail, No coverage, matching
    fd.flush()
    fd.close()
    time.sleep(0.5)
    fd = open('logs/{}/run.{}.log'.format(out_env,it), 'r')
    lines = fd.readlines()
    fd.close()
    match = True
    ret = -1
    error_list = []
    for l in lines:
        if "error" in l:
            match = False
            error_list.append(l)
        elif "CRTLCOV" in l:
            print(l)
            cov = int(l.split(':')[1].strip())
            ret = 0 #success in coverage collect
            if not match:
                #is it legit mismatch or known issue?
                match = check_mismatch_BP(error_list,elf_file) 
            break
    os.chdir(cwd)
    if ret==-1:
        print("Sth went wrong!?")
    print("Cov: " , cov, " Match: " , match)
    return (ret,cov,match)
    

def save_err(out: str, proc_num: int, manager: procManager, stop_code: int, it):

    if stop_code == proc_state.NORMAL:
        return

    status = proc_state.tpe[stop_code]

    manager.P('state')
    fd = open(out + '/fuzz_log', 'a')
    fd.write('[ProcessorFuzz] Thread {}: {} occurred\n'.format(proc_num, status))
    fd.close()

    if not os.path.isdir(out + '/err'):
        os.makedirs(out + '/err')
    manager.V('state')

    shutil.copyfile(out + '/tests/.input_{}.si'.format(it),
                    out + '/err/err_{}_{}.si'.format(status, it))


def isa_timeout(out, stop, proc_num, it):
    if not os.path.isdir(out + '/isa_timeout'):
        os.makedirs(out + '/isa_timeout')

    #shutil.copy(out + '/tests/.input_{}.elf'.format(it), out + '/isa_timeout/timeout_{}.elf'.format(it))
    #shutil.copy(out + '/tests/.input_{}.S'.format(it), out + '/isa_timeout/timeout_{}.S'.format(it))

    ps = psutil.Process()
    children = ps.children(recursive=True)
    for child in children:
        try: os.kill(child.pid, signal.SIGKILL) # SIGKILL
        except: continue

    stop[0] = proc_state.ERR_ISA_TIMEOUT

def run_isa_test(isaHost, isa_input, stop, out, proc_num, assert_intr=False, log='spike.log', name=''):
    ret = proc_state.NORMAL
   
    timer = Timer(ISA_TIME_LIMIT, isa_timeout, [out, stop, proc_num, name])
    timer.start()
    isa_ret = isaHost.run_test(isa_input, assert_intr, log)
    timer.cancel()

    if stop[0] == proc_state.ERR_ISA_TIMEOUT:
        stop[0] = proc_state.NORMAL
        ret = proc_state.ERR_ISA_TIMEOUT
    elif isa_ret != 0:
        stop[0] = proc_state.ERR_ISA_ASSERT
        ret = proc_state.ERR_ISA_ASSERT

    return ret


def debug_print(message, debug, highlight=False):
    if highlight:
        print('\x1b[1;31m' + message + '\x1b[1;m')
    elif debug:
        print(message)

def save_file(file_name, mode, line):
    fd = open(file_name, mode)
    fd.write(line)
    fd.close()

def save_mismatch(base, proc_num, out, sim_input: simInput, data: list, num, it): #, elf, asm, hexfile, mNum):
    sim_input.save(out + '/sim_input/id_{}.si'.format(num), data)

    elf = base + '/tests/.input_{}.elf'.format(it)
    asm = base + '/tests/.input_{}.S'.format(it)
    hexfile = base + '/tests/.input_{}.hex'.format(it)

    shutil.copy(elf, out + '/elf/id_{}.elf'.format(num))
    shutil.copy(asm, out + '/asm/id_{}.S'.format(num))
    shutil.copy(hexfile, out + '/hex/id_{}.hex'.format(num))

def setup(dut, toplevel, template, out, proc_num, debug, minimizing=False, no_guide=False):
    mutator = rvMutator(corpus_size=1000, no_guide=no_guide)

    cc = 'riscv64-unknown-elf-gcc'
    elf2hex = 'riscv64-unknown-elf-elf2hex'
    preprocessor = rvPreProcessor(cc, elf2hex, template, out, proc_num)

    spike = os.environ['SPIKE']
    isa_sigfile = out + '/.isa_sig_{}.txt'.format(proc_num)
    rtl_sigfile = out + '/.rtl_sig_{}.txt'.format(proc_num)

    if debug: spike_arg = ['-l']
    else: spike_arg = []

    isaHost = rvISAhost(spike, spike_arg, isa_sigfile)
    rtlHost = rvRTLhost(dut, toplevel, rtl_sigfile, debug=debug)

    checker = sigChecker(isa_sigfile, rtl_sigfile, debug, minimizing)

    return (mutator, preprocessor, isaHost, rtlHost, checker)
