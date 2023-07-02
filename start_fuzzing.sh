#!/bin/bash -l
BATCHNO=$1
ITERS=$2

echo "batch" 
echo $BATCHNO
mkdir -p Fuzzer/batch${BATCHNO}/trace Fuzzer/batch${BATCHNO}/tests
export VERILATOR_ROOT=/root/verilator
source env.sh
cd Fuzzer
python3 -m venv penv
source penv/bin/activate
#pip install -r requirements.txt
export SPIKE="/root/lowrisc/bin/spike"
#export SPIKE="/root/riscv-isa-sim-all-csr/build/bin/spike"
export BP_ROOT="/root/black-parrot-sim"
export BP_EN=1
export NO_ISA_GUIDE=0
export FP_CSR=0
export ALL_CSR=0
export RUN_MUTATED_TRANSITION=0
export MUTATE_FINER=0
export MEDELEG_MOD=0

make SIM_BUILD=build_boom_batch${BATCHNO} VFILE=SmallBoomTile_v1.2_state TOPLEVEL=BoomTile NUM_ITER=${ITERS} OUT=batch${BATCHNO} TRACE=batch${BATCHNO}/trace/ |& tee run.bp.${BATCHNO}.log
