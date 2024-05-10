#!/usr/bin/python3

import glob
import os
import shutil
import sys
from time import perf_counter

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

import inspection
import solidifi
from common_config import bug_types, contract_names_per_file, contract_orders

# tools = ["Oyente", "Securify", "Mythril", "Smartcheck", "Manticore","Slither"]
tools = []


def evaluate_tools():

    if os.path.isdir("buggy"):
        shutil.rmtree("buggy")

    # inject bug types in all contracts for each tool
    # To inject bug, use solr 0.5.12
    os.system("solc-select install 0.5.12")
    os.system("solc-select use 0.5.12")

    for tool in tools:
        for contract_order in contract_orders:
            tool_bugs = [bugs["bugs"] for bugs in bug_types if bugs["tool"] == tool]
            for bug_type in tool_bugs[0]:
                time = solidifi.interior_main(
                    "-i", "contracts/" + str(contract_order) + ".sol", bug_type
                )

        tool_main_dir = os.path.join("tool_results", tool)
        tool_buggy_sc = os.path.join(tool_main_dir, "analyzed_buggy_contracts")
        os.system("rm -rf {0}".format(tool_buggy_sc))
        os.makedirs(tool_buggy_sc, exist_ok=True)
        mv_cmd = "mv buggy/* {0}".format(tool_buggy_sc)
        os.system(mv_cmd)

    # check the generated buggy contracts

    for tool in tools:

        tool_main_dir = os.path.join("tool_results", tool)
        tool_buggy_sc = os.path.join(tool_main_dir, "analyzed_buggy_contracts")
        tool_bugs = [bugs["bugs"] for bugs in bug_types if bugs["tool"] == tool]

        for bug_type in tool_bugs[0]:
            tool_results = os.path.join(tool_buggy_sc, bug_type)
            tool_result_per_bug = os.path.join(tool_results, "results")
            os.makedirs(tool_result_per_bug, exist_ok=True)
            injected_scs = os.path.join(tool_buggy_sc, bug_type)

            for buggy_sc in glob.glob(injected_scs + "/*.sol"):
                buggy_sc_filepath, buggy_sc_filename = os.path.split(buggy_sc)
                result_file = tool_result_per_bug + "/" + buggy_sc_filename + ".txt"
                if tool in ("Slither", "Oyente"):
                    result_file = (
                        tool_result_per_bug + "/" + buggy_sc_filename + ".json"
                    )

                if tool == "Oyente":
                    # Oyente command
                    tool_cmd = 'docker run -i -t -v {0} luongnguyen/oyente bash -c " cd oyente ; python oyente.py -ce -j -s ../contracts/{1} " >{2} '.format(
                        os.path.join(os.getcwd(), injected_scs) + ":/oyente/contracts",
                        buggy_sc_filename,
                        result_file,
                    )
                    os.system(tool_cmd)

                elif tool == "Securify":

                    # Securify command
                    tool_cmd = "timeout 900 java -jar /securify/build/libs/securify.jar -fs {0} > {1}".format(
                        buggy_sc, result_file
                    )
                    os.system(tool_cmd)

                elif tool == "Mythril":
                    # Mythril command
                    tool_cmd = "myth  analyze {0} --execution-timeout 900 > {1}".format(
                        buggy_sc, result_file
                    )
                    os.system(tool_cmd)

                elif tool == "Smartcheck":
                    # Smartcheck command
                    # ""If you are using nmp installation""
                    tool_cmd = "smartcheck -p {0} > {1}".format(buggy_sc, result_file)
                    os.system(tool_cmd)

                elif tool == "Manticore":
                    cs_names = [
                        names["names"]
                        for names in contract_names_per_file
                        if names["file"] == buggy_sc_filename
                    ]

                    for cs_name in cs_names[0]:
                        result_file = (
                            tool_result_per_bug
                            + "/"
                            + buggy_sc_filename[0 : len(buggy_sc_filename) - 4]
                            + "."
                            + cs_name
                            + ".txt"
                        )
                        # Manticore command
                        tool_cmd = "manticore --workspace /tmp/manticore --core.timeout 900 --evm.sha3timeout 60 --smt.timeout 60 --core.mprocessing threading --smt.memory 4000 --contract {0} {1}".format(
                            cs_name, buggy_sc
                        )
                        os.system(tool_cmd)
                        workspace = "/tmp/manticore"
                        src_file = os.path.join(workspace, "global.findings")
                        if os.path.isfile(src_file):
                            cp_cmd = "cp {0} {1}".format(src_file, result_file)
                            os.system(cp_cmd)
                            rm_cmd = "rm -rf {0}".format(workspace)
                            os.system(rm_cmd)

                elif tool == "Slither":
                    # Slither command
                    tool_cmd = "slither {0} --json {1}".format(buggy_sc, result_file)
                    os.system(tool_cmd)

                elif tool == "CrossFuzz":
                    tested_contract_names: list[str] = [
                        file["names"]
                        for file in contract_names_per_file
                        if file["file"] == buggy_sc_filename
                    ][0]
                    for contract_name in tested_contract_names:
                        result_file = (
                            tool_result_per_bug
                            + "/"
                            + buggy_sc_filename
                            + f".{contract_name}"
                            + ".json"
                        )
                        cross_fuzz_cmd_opts = " ".join(
                            [
                                buggy_sc,  # sol file path, which is the file path to be fuzzed
                                contract_name,  # contract name, which is the contract to be fuzzed
                                "0.5.12",  # solc_version
                                "1000",  # max transaction length, e.g., 10
                                "60",  # timeout, e.g., 60(s)
                                result_file,
                                "/usr/local/bin/solc",  # solc_path
                                "auto",  # constructor_params_path
                                "0",  # trans_duplication
                            ]
                        )
                        # cross_fuzz_fuzzer_opts = (
                        #     f" -s {buggy_sc}"
                        #     f" -c {contract_name}"
                        #     f" --solc v0.5.12"
                        #     f" --evm byzantium"
                        #     f" -t 60"
                        #     f" --result {result_file}"
                        #     f" --cross-contract 1"
                        #     f" --open-trans-comp 1"
                        #     f" --depend-contracts ''"
                        #     f" --constructor-args ''"
                        #     f" --constraint-solving 1"
                        #     f" --max-individual-length 10"
                        #     f" --solc-path-cross '/usr/local/bin/solc'"
                        #     f" --p-open-cross 80"
                        #     f" --cross-init-mode 1"
                        #     f" --trans-mode 1"
                        #     f" --duplication 0"
                        # )

                        tool_cmd = " ".join(
                            [
                                "python3",
                                "./CrossFuzz/CrossFuzz.py",
                                cross_fuzz_cmd_opts,
                            ]
                        )
                        os.system(tool_cmd)

                """
                To evaluate other tools, add the command to run each tool in this area using the 3-line code pattern as below. 
                You just need to replace values surrounded by <>

                elif tool == '<ToolName>':              
                    tool_cmd = "<command to run the tool>"
                    os.system(tool_cmd)
                """


if __name__ == "__main__":
    # if 1 != len(sys.argv):
    # if sys.argv[1] in ("--help", "-h"):
    #     printUsage(sys.argv[0])

    tools = sys.argv[1].split(",")
    # tools = ["Manticore"]
    # tools = ["Slither"]
    # tools = ["CrossFuzz"]

    start = perf_counter()

    evaluate_tools()
    inspection.Inspect_results(tools)

    end = perf_counter()

    print(f"Total process cost {end - start} seconds")

    # else:
    # print("wrong number of parameters")
