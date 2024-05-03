#! /usr/bin/bash

# python3 -m venv venv
# source venv/bin/activate
pip3 install wheel
pip3 install -r requirements.txt
solc-select install 0.4.26
solc-select use 0.4.26
mkdir -p CrossFuzz/fuzzer/result/

python3 ./CrossFuzz/CrossFuzz.py ./tool_results/Slither/analyzed_buggy_contracts/Re-entrancy/buggy_1.sol HotDollarsToken 0.5.12 10 60 ./tool_results/Slither/analyzed_buggy_contracts/Re-entrancy/results/buggy_1.sol.HotDollarsToken.json /usr/local/bin/solc auto 0

python3 ./CrossFuzz/fuzzer/main.py -s ./tool_results/Slither/analyzed_buggy_contracts/Re-entrancy/buggy_1.sol -c EIP20Interface --solc v0.5.12 --evm byzantium -t 60 --result ./tool_results/Slither/analyzed_buggy_contracts/Re-entrancy/results/buggy_1.sol.EIP20Interface.json --cross-contract 1 --open-trans-comp 1 --depend-contracts --constructor-args  --constraint-solving 1 --max-individual-length 1000 --solc-path-cross /usr/local/bin/solc --p-open-cross 80 --cross-init-mode 1 --trans-mode 1 --duplication 0

python3 ./CrossFuzz/CrossFuzz.py ./contracts/5.sol Ownable 0.4.26 1 5 ./out.json /usr/local/bin/solc auto 0