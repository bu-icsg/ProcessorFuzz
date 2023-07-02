import time
import random
import sys
import glob, os

from cocotb.decorators import coroutine
from RTLSim.host import ILL_MEM, SUCCESS, TIME_OUT, ASSERTION_FAIL
from datetime import datetime, timedelta
from src.mutator import GENERATION


from src.utils import *
from src.multicore_manager import proc_state

RISCVDV_SCRIPTS = os.path.abspath("src/scripts/")
sys.path = ( [ RISCVDV_SCRIPTS ] + sys.path)

from spike_log_to_trace_csv import process_spike_sim_log

BP_ROOT = out_env = os.environ['BP_ROOT'] #provided in submit_job.sh script
bp_en = os.environ['BP_EN'] == '1' #provided in submit_job.sh script
run_mutated_transition_en = os.environ['RUN_MUTATED_TRANSITION'] == '1'
mutate_finer_en = os.environ['MUTATE_FINER'] == '1'
no_isa_guide = os.environ['NO_ISA_GUIDE'] == '1'

@coroutine
def Run(dut, toplevel,
		num_iter=1, template='Template', in_file=None,
		out='output', record=False, cov_log=None,
		multicore=0, manager=None, proc_num=0, start_time=0, start_iter=0, start_cov=0,
		prob_intr=0, no_guide=False, debug=False):

	print("Current configuration:")
	print("run_mutated_transition: " + str(run_mutated_transition_en))
	print("mutate_finer_en: " + str(mutate_finer_en))
	assert toplevel in ['RocketTile', 'BoomTile' ], \
		'{} is not toplevel'.format(toplevel)

	random.seed(time.time() * (proc_num + 1))

	(mutator, preprocessor, isaHost, rtlHost, checker) = \
		setup(dut, toplevel, template, out, proc_num, debug, no_guide=no_guide)

	if in_file: num_iter = 1

	stop = [ proc_state.NORMAL ]
	mNum = 0
	cNum = 0
	iNum = 0
	mis_count = 0
	last_coverage = 0
	coverage = 0
	preprocessor.bp_en = bp_en
	preprocessor.bp_root = BP_ROOT
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
		#if random.random() < prob_intr:
		#	assert_intr = True
		print("Id_p: " + str(it))
		if in_file: (sim_input, data, assert_intr) = mutator.read_siminput(in_file)
		else: (sim_input, data) = mutator.get(it, assert_intr)
		print("Id_a: " + str(sim_input.it))

		if debug:
			print('[ProcessorFuzz] Fuzz Instructions')
			for inst, INT in zip(sim_input.get_insts(), sim_input.ints + [0]):
				print('{:<50}{:04b}'.format(inst, INT))

		(isa_input, rtl_input, symbols) = preprocessor.process(sim_input, data, assert_intr, it)

		if isa_input and rtl_input:
			isa_log = out + "/trace/isa_" + str(it) + ".log"
			name = str(sim_input.it)+sim_input.name_suffix
			ret = run_isa_test(isaHost, isa_input, stop, out, proc_num, assert_intr, isa_log, name)
			if ret == proc_state.ERR_ISA_TIMEOUT: 
				try:
					os.remove(isa_log)
					input_files = out + '/tests/.input_{}{}.*'.format(it, sim_input.name_suffix)
					for ifi in glob.glob(input_files): #recomment
						os.remove(ifi) #recomment
					print("ISA Timeout")
				except:
					print("ISA Timeout, no file!")
				continue
			elif ret == proc_state.ERR_ISA_ASSERT: 
				print("ISA Assert Error")
				continue
			else:
				if not no_isa_guide:
					trns, mut_labels = extract_transitions(isa_log, out, it, name)
					print("Mutatation time:")
					print(mut_labels)
					sim_input.mut_labels = mut_labels
				isa_csv = out+"/trace/isa_"+str(it)+".csv"
				process_spike_sim_log(isa_log, isa_csv)

				if not no_isa_guide and trns==0 : # Don't do RTL sim if the test does not have unique transitions
					if not run_mutated_transition_en or (run_mutated_transition_en and mutator.phase == GENERATION):
						input_files = out + '/tests/.input_{}{}.*'.format(it, sim_input.name_suffix)
						for ifi in glob.glob(input_files): #recomment
							os.remove(ifi) #recomment
							#print("Removing ",ifi)
						input_files = out + '/trace/isa_{}.*'.format(it)
						for ifi in glob.glob(input_files):
							os.remove(ifi)
						continue 
			try:
				if bp_en:
					(ret, tcov, match) = bp_run_test(BP_ROOT, out + '/tests/.input_' + name + '.elf', it)
					coverage = coverage + tcov
				else:
					(ret, coverage) = yield rtlHost.run_test(rtl_input, assert_intr, it)
			except:
				stop[0] = proc_state.ERR_RTL_SIM
				print("Oops!", sys.exc_info()[0], "occurred.")
				print("ERROR: Test run failed")
				continue

			rtl_log = out+"/trace/rtl_"+str(it)+".log"
			if not bp_en:
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
			if not no_isa_guide:
				print("Iteration: {}, ElapsedTime: {}, Coverage: {}, Transitions: {}".format(it, ct-now, coverage, trns))
			else:
				print("Iteration: {}, ElapsedTime: {}".format(it, ct-now))
			if not bp_en:
				cause = '-'
				match = False
			if ret == SUCCESS and not bp_en:
				match = checker.check(symbols)
			elif ret == ILL_MEM and not bp_en:
				match = True
				debug_print('[ProcessorFuzz] Memory access outside DRAM -- {}'. \
							format(iNum), debug, True)
				if record:
					save_mismatch(out, proc_num, out + '/illegal',
								  sim_input, data, iNum, it)
				iNum += 1

			if (not match and not bp_en) or ret not in [SUCCESS, ILL_MEM]:
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
			

			if not no_isa_guide and trns>0:
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
			# Remove symbols and hex files
			input_files = out + '/tests/.input_{}{}.symbols'.format(it, sim_input.name_suffix)
			#print(input_files)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.hex'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.S'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/tests/.input_{}{}.elf'.format(it, sim_input.name_suffix)
			os.remove(input_files)
			input_files = out + '/trace/isa_{}.csv'.format(it)
			os.remove(input_files)
			input_files = out + '/trace/isa_{}.log'.format(it)
			os.remove(input_files)
			mutator.update_phase(it)

		else:
			stop[0] = proc_state.ERR_COMPILE
			# Compile failed
			print("ERROR: Compile failed")
			continue

	debug_print('[ProcessorFuzz] Stop Fuzzing', debug)
	print("MISMATCH COUNT: ",mis_count)
