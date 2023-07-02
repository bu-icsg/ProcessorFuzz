import time
import random
import sys
import glob, os

from cocotb.decorators import coroutine
from RTLSim.host import ILL_MEM, SUCCESS, TIME_OUT, ASSERTION_FAIL
from datetime import datetime, timedelta


from src.utils import *
from src.multicore_manager import proc_state

RISCVDV_SCRIPTS = os.path.abspath("src/scripts/")
sys.path = ( [ RISCVDV_SCRIPTS ] + sys.path)

from spike_log_to_trace_csv import process_spike_sim_log

@coroutine
def Run(dut, toplevel,
		num_iter=1, template='Template', in_file=None,
		out='output', record=False, cov_log=None,
		multicore=0, manager=None, proc_num=0, start_time=0, start_iter=0, start_cov=0,
		prob_intr=0, no_guide=False, seed_dir=None, debug=False, run_elf=None, ALL_CSR=False, FP_CSR=False):

	assert toplevel in ['RocketTile', 'BoomTile' ], \
		'{} is not toplevel'.format(toplevel)
	random.seed(time.time() * (proc_num + 1))

	(mutator, preprocessor, isaHost, rtlHost, checker) = \
		setup(dut, toplevel, template, out, proc_num, debug, no_guide=no_guide)

	if in_file or run_elf: num_iter = 1

	if seed_dir:
		seed_list = glob.glob(seed_dir+'/.input_*.si')
		num_iter = len(seed_list)

	stop = [ proc_state.NORMAL ]
	mNum = 0
	cNum = 0
	iNum = 0
	mis_count = 0
	last_coverage = 0
	coverage = 0
	debug_print('[ProcessorFuzz] Start Fuzzing', debug)

	if multicore:
		yield manager.cov_restore(dut)

	now = datetime.now()
	ct = datetime.now()

	for it in range(1, num_iter+1):
		debug_print('[ProcessorFuzz] Iteration [{}]'.format(it), debug)

		if multicore:
			if it == 0:
				mutator.update_corpus(out + '/corpus', 1000)
			elif it % 1000 == 0:
				mutator.update_corpus(out + '/corpus')

		assert_intr = False

		if in_file: 
			(sim_input, data, assert_intr) = mutator.read_siminput(in_file)
		elif seed_dir: 
			seed_i = glob.glob(seed_dir+'/.input_'+str(it)+'_*.si')
			if len(seed_i)==0:
				continue
			(sim_input, data, assert_intr) = mutator.read_siminput(seed_i[0])
		else: 
			(sim_input, data) = mutator.get(it, assert_intr)

		if debug:
			print('[ProcessorFuzz] Fuzz Instructions')
			for inst, INT in zip(sim_input.get_insts(), sim_input.ints + [0]):
				print('{:<50}{:04b}'.format(inst, INT))

		(isa_input, rtl_input, symbols) = preprocessor.process(sim_input, data, assert_intr, it, run_elf)

		if seed_dir:
			input_files = out + '/tests/.input_{}{}.symbols'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.hex'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.S'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.si'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			continue

		if isa_input and rtl_input:
			isa_log = out + "/trace/isa_" + str(it) + ".log"
			name = str(sim_input.it)+sim_input.name_suffix
			ret = run_isa_test(isaHost, isa_input, stop, out, proc_num, assert_intr, isa_log, name)
			if ret == proc_state.ERR_ISA_TIMEOUT: 
				print("ISA Timeout")
				continue
			elif ret == proc_state.ERR_ISA_ASSERT: 
				print("ISA Assert Error")
				continue
			else:
				trns = extract_transitions(isa_log, out, it, ALL_CSR, FP_CSR)
				isa_csv = out+"/trace/isa_"+str(it)+".csv"
				process_spike_sim_log(isa_log, isa_csv)

				if trns==0: #Don't do RTL sim if the test does not have unique transitions
					input_files = out + '/tests/.input_{}{}.*'.format(it, sim_input.name_suffix)
					for ifi in glob.glob(input_files):
						os.remove(ifi)
					input_files = out + '/trace/isa_{}.*'.format(it)
					for ifi in glob.glob(input_files):
						os.remove(ifi)
					continue


			try:
				(ret, coverage) = yield rtlHost.run_test(rtl_input, assert_intr, it)
			except:
				stop[0] = proc_state.ERR_RTL_SIM
				print("ERROR: Test run failed")
				continue

			rtl_log = out+"/trace/rtl_"+str(it)+".log"
			chk = trace_compare(isa_csv, rtl_log, toplevel)
			if chk==-1: mis_count += 1

			if assert_intr and ret == SUCCESS:
				(intr_prv, epc) = checker.check_intr(symbols)
				if epc != 0:
					preprocessor.write_isa_intr(isa_input, rtl_input, epc)
					ret = run_isa_test(isaHost, isa_input, stop, out, proc_num, True, isa_log, it)
					if ret == proc_state.ERR_ISA_TIMEOUT: 
						print("ERROR: ISA Timeout")
						continue
					elif ret == proc_state.ERR_ISA_ASSERT: 
						print("ERROR: ISA Assert")
						continue
				else: continue
			ct = datetime.now()
			print("Iteration: {}, ElapsedTime: {}, Coverage: {}, Transitions: {}".format(it, ct-now, coverage, trns))
			cause = '-'
			match = False
			if ret == SUCCESS:
				match = checker.check(symbols)
			elif ret == ILL_MEM:
				match = True
				debug_print('[ProcessorFuzz] Memory access outside DRAM -- {}'. \
							format(iNum), debug, True)
				if record:
					save_mismatch(out, proc_num, out + '/illegal',
								  sim_input, data, iNum, it)
				iNum += 1

			if (not match) or ret not in [SUCCESS, ILL_MEM]:
				if multicore:
					mNum = manager.read_num('mNum')
					manager.write_num('mNum', mNum + 1)

				if record:
					save_mismatch(out, proc_num, out + '/mismatch',
								  sim_input, data, mNum, it)

				mNum += 1
				if ret == TIME_OUT: cause = 'Timeout'
				elif ret == ASSERTION_FAIL: cause = 'Assertion fail'
				else: cause = 'Mismatch'

				debug_print('[ProcessorFuzz] Bug -- {} [{}]'. \
							format(mNum, cause), debug, not match or (ret != SUCCESS))
			

			if trns>0:
				if multicore:
					cNum = manager.read_num('cNum')
					manager.write_num('cNum', cNum + 1)

				if record:
					save_file(cov_log, 'a', '{:<10}\t{:<10}\t{:<10}\n'.
							  format(time.time() - start_time, start_iter + it,
									 start_cov + coverage))
					sim_input.save(out + '/corpus/id_{}.si'.format(cNum))

				cNum += 1
				mutator.add_corpus(sim_input)
				last_coverage = coverage
			# Remove symbols and hex files to save storage
			input_files = out + '/tests/.input_{}{}.symbols'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.hex'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.S'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.elf'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/trace/isa_{}.log'.format(it)
			os.remove(input_files)
			input_files = out + '/trace/isa_{}.csv'.format(it)
			os.remove(input_files)
			input_files = out + '/trace/rtl_{}.log'.format(it)
			os.remove(input_files)
			mutator.update_phase(it)

		else:
			stop[0] = proc_state.ERR_COMPILE
			# Compile failed
			print("ERROR: Compile failed")
			continue

	if multicore:
		save_err(out, proc_num, manager, stop[0])
		manager.set_state(proc_num, stop[0])

	debug_print('[ProcessorFuzz] Stop Fuzzing', debug)
	print("MISMATCH COUNT: ",mis_count)

	if multicore:
		yield manager.cov_store(dut, proc_num)
		manager.store_covmap(proc_num, start_time, start_iter, num_iter)
