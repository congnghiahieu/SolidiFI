import json
import shutil
import sys
import os
from typing import Any

import config
from comp import analysis_depend_contract, analysis_main_contract_constructor


def run(
    _file_path: str,
    result_save_file: str,
    _main_contract,
    solc_version: str,
    evm_version: str,
    timeout: int,
    _depend_contracts: list,
    max_individual_length: int,
    _constructor_args: list,
    _solc_path: str,
    _duplication: str = "0",
):
    depend_contracts_str = " ".join(_depend_contracts)
    constructor_str = " ".join(_constructor_args)
    cmd = (
        f"{PYTHON} {FUZZER}"
        f" -s {_file_path}"
        f" -c {_main_contract}"
        f" --solc v{solc_version}"
        f" --evm {evm_version}"
        f" -t {timeout}"
        f" --result {result_save_file}"
        f" --cross-contract 1"
        f" --open-trans-comp 1"
        f" --depend-contracts {depend_contracts_str}"
        f" --constructor-args {constructor_str}"
        f" --constraint-solving 1"
        f" --max-individual-length {max_individual_length}"
        f" --solc-path-cross {_solc_path}"
        f" --p-open-cross 80"
        f" --cross-init-mode 1"
        f" --trans-mode 1"
        f" --duplication {_duplication}"
    )
    print(cmd)
    os.popen(cmd).readlines()  # run CrossFuzz.py
    return result_save_file


def run_cve():
    sol_files, file_with_cross_fuzz_runtime_error = [], []
    with open("./collectContracts.json", "r") as r_file:
        sol_files: list[Any] = json.load(r_file)
    print("-------------------------------------")
    print(f"Number of contract file in collectContracts.json: {len(sol_files)}")
    print("-------------------------------------")
    for sol_file in sol_files:
        file_path = sol_file["filepath"]  # absolute path
        assert isinstance(sol_file, dict)
        solc_version = "0.5.12"
        evm_version = "byzantium"
        timeout = 1
        for contract_name in sol_file["contracts"]:
            print("----------------------------------")
            print(contract_name)
            print("----------------------------------")
            try:
                solc_path = config.SOLC_BIN_PATH
                _depend_contracts, _sl = analysis_depend_contract(
                    file_path=file_path,
                    _contract_name=contract_name,
                    _solc_version=solc_version,
                    _solc_path=solc_path,
                )
                max_individual_length = 1000
                _constructor_args = analysis_main_contract_constructor(
                    file_path=file_path, _contract_name=contract_name, sl=_sl
                )
                run(
                    file_path,
                    "./CrossFuzz/fuzzer/result/res.json",
                    contract_name,
                    solc_version,
                    evm_version,
                    timeout,
                    _depend_contracts,
                    max_individual_length,
                    _constructor_args,
                    _solc_path=config.SOLC_BIN_PATH,
                )
            except Exception as e:
                file_with_cross_fuzz_runtime_error.append(
                    {
                        "file_path": file_path,
                        "contract_name": contract_name,
                        "error_msg": str(e),
                    }
                )
    if file_with_cross_fuzz_runtime_error:
        print("-------------------------------------")
        print(
            f"Number of contract file that cause CrossFuzz error in crossFuzzErrors.json: {len(file_with_cross_fuzz_runtime_error)}"
        )
        print("-------------------------------------")
        with open("crossFuzzRuntimeErrors.json", "w") as w_file:
            json.dump(file_with_cross_fuzz_runtime_error, w_file, ensure_ascii=False)


def run_cve_test():
    sol_files, file_with_cross_fuzz_runtime_error = [], []
    with open("./collectContracts.json", "r") as r_file:
        sol_files: list[Any] = json.load(r_file)
    print("-------------------------------------")
    print(f"Number of contract file in collectContracts.json: {len(sol_files)}")
    print("-------------------------------------")
    for sol_file in sol_files:
        file_path = sol_file["filepath"]  # absolute path
        print(file_path)
        assert isinstance(sol_file, dict)
        solc_version = sol_file.get("version", "^0.4.26").strip("^")
        evm_version = "byzantium"
        timeout = 1
        for contract_name in sol_file["contracts"]:
            print("----------------------------------")
            print(contract_name)
            print("----------------------------------")
            try:
                solc_path = config.SOLC_BIN_PATH
                _depend_contracts, _sl = analysis_depend_contract(
                    file_path=file_path,
                    _contract_name=contract_name,
                    _solc_version=solc_version,
                    _solc_path=solc_path,
                )
                max_individual_length = 1000
                _constructor_args = analysis_main_contract_constructor(
                    file_path=file_path, _contract_name=contract_name, sl=_sl
                )
                run(
                    file_path,
                    "./CrossFuzz/fuzzer/result/res.json",
                    contract_name,
                    solc_version,
                    evm_version,
                    timeout,
                    _depend_contracts,
                    max_individual_length,
                    _constructor_args,
                    _solc_path=config.SOLC_BIN_PATH,
                )
            except Exception as e:
                file_with_cross_fuzz_runtime_error.append(
                    {
                        "file_path": file_path,
                        "contract_name": contract_name,
                        "error_msg": str(e),
                    }
                )
    if file_with_cross_fuzz_runtime_error:
        print("-------------------------------------")
        print(
            f"Number of contract file that cause CrossFuzz error in crossFuzzErrors.json: {len(file_with_cross_fuzz_runtime_error)}"
        )
        print("-------------------------------------")
        with open("crossFuzzRuntimeErrors.json", "w") as w_file:
            json.dump(file_with_cross_fuzz_runtime_error, w_file, ensure_ascii=False)


def test_run():
    # absolute path
    _file_path = "./examples/T.sol"
    _main_contract = "E"
    solc_version = "0.4.26"
    evm_version = "byzantium"
    timeout = 10
    solc_path = config.SOLC_BIN_PATH
    _depend_contracts, _sl = analysis_depend_contract(
        file_path=_file_path,
        _contract_name=_main_contract,
        _solc_version=solc_version,
        _solc_path=solc_path,
    )
    max_individual_length = 10
    _constructor_args = analysis_main_contract_constructor(
        file_path=_file_path, _contract_name=_main_contract, sl=_sl
    )
    run(
        _file_path,
        "./CrossFuzz/fuzzer/result/res.json",
        _main_contract,
        solc_version,
        evm_version,
        timeout,
        _depend_contracts,
        max_individual_length,
        _constructor_args,
        _solc_path=config.SOLC_BIN_PATH,
    )


def cli():
    p = sys.argv[1]  # sol file path, which is the file path to be fuzzed
    c_name = sys.argv[2]  # contract name, which is the contract to be fuzzed
    solc_version = sys.argv[3]  # only support 0.4.24, 0.4.26, 0.6.12, 0.8.4
    max_trans_length = int(sys.argv[4])  # max transaction length, e.g., 10
    fuzz_time = int(sys.argv[5])  # fuzz time, e.g., 60(s)
    res_saved_path = sys.argv[6]  # e.g., ./xxxx.json
    solc_path = sys.argv[7]  # solc path
    constructor_params_path = sys.argv[8]  # e.g., Auto or "examples/p.json"
    trans_duplication = sys.argv[
        9
    ]  # e.g., 0 if you don't want to duplicate transactions, otherwise 1

    _depend_contracts, _sl = analysis_depend_contract(
        file_path=p,
        _contract_name=c_name,
        _solc_version=solc_version,
        _solc_path=solc_path,
    )

    # if len(_depend_contracts) <= 0:
    #     print("No depend contracts")
    #     sys.exit(-1)

    if constructor_params_path != "auto":
        _constructor_args = []
        for p_name, p_detail in json.load(
            open(constructor_params_path, "r", encoding="utf-8")
        ).items():
            _constructor_args.append(f"{p_name} {p_detail['type']} {p_detail['value']}")
    else:
        _constructor_args = analysis_main_contract_constructor(
            file_path=p, _contract_name=c_name, sl=_sl
        )

    if _constructor_args is None:
        print("No constructor")
        sys.exit(-2)

    res = run(
        p,
        res_saved_path,
        c_name,
        solc_version,
        "byzantium",
        fuzz_time,
        _depend_contracts,
        max_trans_length,
        _constructor_args,
        _solc_path=solc_path,
        _duplication=trans_duplication,
    )
    # shutil.copyfile(res, res_saved_path)  # move result json file to the specified path


if __name__ == "__main__":
    PYTHON = "python3"  # your python3 path
    FUZZER = "./CrossFuzz/fuzzer/main.py"  # your fuzzer path in this repo
    cli()
    # test_run()
