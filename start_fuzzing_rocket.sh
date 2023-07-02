#!/bin/bash -l
BATCHNO=$1
ITERS=$2

echo "batch" 
echo $BATCHNO
mkdir -p Fuzzer/batch${BATCHNO}/trace Fuzzer/batch${BATCHNO}/tests
export VERILATOR_ROOT=/root/verilator
#source env.sh
export PYTHONPATH=$PWD/Fuzzer:$PWD/Fuzzer/src:$PWD/Fuzzer/RTLSim/src:$PYTHONPATH
cd Fuzzer
#python3 -m venv penv
#source penv/bin/activate
#pip install -r requirements.txt
export SPIKE="/root/lowrisc/bin/spike"
#export SPIKE=/projectnb2/risc-v/riscv-dv-verific/riscv-isa-sim-all-csr/build/spike
#export BP_ROOT="/root/black-parrot-sim"
#export BP_EN=1
#export NO_GUIDE=1
#export RUN_MUTATED_TRANSITION=0
#export MUTATE_FINER=0
#export MEDELEG_MOD=0
export FP_CSR=0
export ALL_CSR=0

# Only enable one config at a time
if [ "$FP_CSR" == "1" ]
then
	echo "[ProcessorFuzz] Using FP_CSR configuration"
	export ALL_CSR=0
elif [ "$ALL_CSR" == '1' ]
then
	echo "[ProcessorFuzz] Using ALL_CSR configuration"
	export FP_CSR=0
	export SPIKE="/root/riscv-isa-sim-all-csr/build/bin/spike"
fi

make SIM_BUILD=build_rocket_batch${BATCHNO} VFILE=RocketTile_latest TOPLEVEL=RocketTile NUM_ITER=${ITERS} OUT=batch${BATCHNO} ALL_CSR=${ALL_CSR} FP_CSR=${FP_CSR} |& tee run.${BATCHNO}.rocket.log
