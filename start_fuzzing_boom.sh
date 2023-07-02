#!/bin/bash -l
BATCHNO=$1
ITERS=$2

echo "batch" 
echo $BATCHNO
mkdir -p Fuzzer/batch${BATCHNO}/trace Fuzzer/batch${BATCHNO}/tests
export VERILATOR_ROOT=/root/verilator
export PYTHONPATH=$PWD/Fuzzer:$PWD/Fuzzer/src:$PWD/Fuzzer/RTLSim/src:$PYTHONPATH
cd Fuzzer
export SPIKE="/root/lowrisc/bin/spike"
#export NO_GUIDE=1
#export RUN_MUTATED_TRANSITION=0
#export MUTATE_FINER=0
#export MEDELEG_MOD=0
export FP_CSR=0
export ALL_CSR=0

# Only enable one config at a time
if [ "$FP_CSR" == "1" ]
then
	export ALL_CSR=0
elif [ "$ALL_CSR" == '1' ]
then
	export FP_CSR=0
	export SPIKE="/root/riscv-isa-sim-all-csr/build/bin/spike"
fi

make SIM_BUILD=build_boom_batch${BATCHNO} VFILE=SmallBoomTile_v1.2_state TOPLEVEL=BoomTile NUM_ITER=${ITERS} OUT=batch${BATCHNO} ALL_CSR=${ALL_CSR} FP_CSR=${FP_CSR} |& tee run.${BATCHNO}.boom.log
