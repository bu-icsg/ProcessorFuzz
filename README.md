# ProcessorFuzz: Processor Fuzzing with Control and Status Registers Guidance

## Summary
ProcessorFuzz is a processor fuzzer tool that identifies "interesting" assembly-based test based on isa-simulator feedback and discovers bugs based on the discrepancies between ISA and RTL simulation. The project is [published](https://ieeexplore.ieee.org/document/10133714) in 2023 IEEE International Symposium on Hardware Oriented Security and Trust (HOST). ProcessorFuzz's implementation is based on a previous work, [DIFUZZRTL](https://github.com/compsec-snu/difuzz-rtl).

## Setup
ProcessorFuzz uses many other projects including spike, dromajo, rocket, boom, blackparrot. To prevent setup issues, we generated a docker image and tested that image on ubuntu 18.04.
Download the docker image from this [link](https://drive.google.com/file/d/1fdq18U2CvbaV9QxFMjuFxF5nmL9CrBxj/view?usp=sharing) and execute the following command on ubuntu machine that has docker.
```
docker load < processorfuzz_docker_img.tar
```
### ProcessorFuzz Source
ProcessorFuzz fuzzer source for Rocket and BOOM cores are in the main branch of this repo while the ProcessorFuzz source for fuzzing Black-Parrot processor in in the BP brnach. 


## Quick start

For fuzzing Rocket core in the docker image, execute the start_fuzzing_rocket.sh script with the name (or number) of the batch and the number of iterations for the fuzzing session. 
For example, to run a fuzzing session with the batch name "1" with 100 test iterations. 
```
cd /root/processorfuzz/main/
./start_fuzzing_rocket.sh 1 100
```

For fuzzing BOOM core in the docker image, execute the start_fuzzing_boom.sh script with the name (or number) of the batch and the number of iterations for the fuzzing session. 
For example, to run a fuzzing session with the batch name "2" with 100 test iterations. 
```
cd /root/processorfuzz/main/
./start_fuzzing_boom.sh 2 100
```

Take a look at the BP branch for the instructions on fuzzing Black-Parrot core. 

### Enabling FP_CSR and ALL_CSR configurations

By default, ProcessorFuzz use the selected mode where transitions of a select set of CSRs are used as coverage.  
You can enable FP_CSR or ALL_CSR configuration by editing the relevant start_fuzzing_*.sh script. 

To enable FP_CSR mode:
```
export FP_CSR=1
export ALL_CSR=0
```
To enable ALL_CSR mode:
```
export FP_CSR=0
export ALL_CSR=1
```
