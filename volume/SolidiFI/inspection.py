#!/usr/bin/python3

# import solidifi
import csv
import glob
import json
import os
import re
import shutil
import sys
from typing import Dict, List, Set

import pandas

import inject_file
from common_config import bug_types, contract_names_per_file, contract_orders

tool_reported_bugs = []
reported_non_injected = []
tools = []
# tools = ["Oyente", "Securify", "Mythril", "Smartcheck","Slither","Manticore"]
main_dir = "tool_results"

securify_bug_codes = [
    {"bug": "Unhandled-Exceptions", "codes": ["UnhandledException"]},
    {"bug": "TOD", "codes": ["TODAmount", "TODReceiver", "TODTransfer"]},
    {"bug": "Unchecked-Send", "codes": ["UnrestrictedEtherFlow"]},
    {"bug": "Re-entrancy", "codes": ["DAOConstantGas", "DAO"]},
]
mythril_bug_codes = [
    {"bug": "Unhandled-Exceptions", "codes": ["Unchecked Call Return Value"]},
    {
        "bug": "Timestamp-Dependency",
        "codes": ["Dependence on predictable environment variable"],
    },
    {"bug": "Overflow-Underflow", "codes": ["Integer Underflow", "Integer Overflow"]},
    {"bug": "tx.origin", "codes": ["Use of tx.origin"]},
    {"bug": "Unchecked-Send", "codes": ["Unprotected Ether Withdrawal"]},
    {
        "bug": "Re-entrancy",
        "codes": [
            "External Call To User-Supplied Address",
            "External Call To Fixed Address",
            "State change after external call",
        ],
    },
]
slither_bug_codes = [
    {"bug": "Unhandled-Exceptions", "codes": ["unchecked-send", "unchecked-lowlevel"]},
    {"bug": "Timestamp-Dependency", "codes": ["timestamp"]},
    {"bug": "tx.origin", "codes": ["tx-origin"]},
    {
        "bug": "Re-entrancy",
        "codes": [
            "reentrancy-benign",
            "reentrancy-eth",
            "reentrancy-unlimited-gas",
            "reentrancy-no-eth",
        ],
    },
]
crossfuzz_bug_codes = [
    {
        "bug": "Unhandled-Exceptions",
        "codes": [
            # "Integer Overflow",
            # "Transaction Order Dependency",
            # "Leaking Ether",
            "Assertion Failure",
            "Unchecked Return Value",
            # "Block Dependency",
        ],
    },
    {
        "bug": "Re-entrancy",
        "codes": [
            # "Integer Overflow",
            # "Transaction Order Dependency",
            "Leaking Ether",
            # "Assertion Failure",
            # "Block Dependency",
            "Reentrancy",
        ],
    },
    {
        "bug": "TOD",
        "codes": [
            "Assertion Failure",
            "Integer Overflow",
            "Transaction Order Dependency",
        ],
    },
    {
        "bug": "Overflow-Underflow",
        "codes": [
            # "Assertion Failure",
            # "Block Dependency",
            "Integer Overflow",
            # "Transaction Order Dependency",
        ],
    },
]
smartcheck_bug_codes = [
    {"bug": "Unhandled-Exceptions", "codes": ["SOLIDITY_UNCHECKED_CALL"]},
    {
        "bug": "Timestamp-Dependency",
        "codes": ["SOLIDITY_EXACT_TIME", "VYPER_TIMESTAMP_DEPENDENCE"],
    },
    {"bug": "Overflow-Underflow", "codes": ["SOLIDITY_UINT_CANT_BE_NEGATIVE"]},
    {"bug": "tx.origin", "codes": ["SOLIDITY_TX_ORIGIN"]},
    {"bug": "Re-entrancy", "codes": ["SOLIDITY_ETRNANCY"]},
]
oyente_bug_codes = [
    {"bug": "Unhandled-Exceptions", "codes": ["Callstack Depth Attack Vulnerability"]},
    {"bug": "Timestamp-Dependency", "codes": ["Timestamp Dependency"]},
    {"bug": "TOD", "codes": ["Transaction-Ordering Dependency"]},
    {"bug": "Re-entrancy", "codes": ["Re-Entrancy Vulnerability"]},
    {"bug": "Overflow-Underflow", "codes": ["Integer Overflow", "Integer Underflow"]},
]
manticore_bug_codes = [
    {
        "bug": "Re-entrancy",
        "codes": [
            "Potential reentrancy vulnerability",
            "Reachable ether leak to sender",
        ],
    },
    {
        "bug": "Overflow-Underflow",
        "codes": [
            "Unsigned integer overflow at ADD instruction",
            "Signed integer overflow at ADD instruction",
            "Unsigned integer overflow at SUB instruction",
            "Signed integer overflow at SUB instruction",
        ],
    },
]


thresholds = [
    {"bug": "Re-entrancy", "threshold": 4},
    {"bug": "Unhandled-Exceptions", "threshold": 3},
    {"bug": "Unchecked-Send", "threshold": 2},
    {"bug": "Timestamp-Dependency", "threshold": 3},
    {"bug": "TOD", "threshold": 2},
    {"bug": "Overflow-Underflow", "threshold": 3},
    {"bug": "tx.origin", "threshold": 2},
]


def Inspect_results(_tools=[]):
    global tool_reported_bugs
    tools = _tools

    oyente_FNs = []
    securify_FNs = []
    mythril_FNs = []
    smartcheck_FNs = []
    slither_FNs = []
    crossfuzz_FNs = []
    manticore_FNs = []

    oyente_FPs = []
    securify_FPs = []
    mythril_FPs = []
    smartcheck_FPs = []
    slither_FPs = []
    crossfuzz_FPs = []
    manticore_FPs = []

    for tool in tools:
        tool_bugs = [bugs["bugs"] for bugs in bug_types if bugs["tool"] == tool][0]
        for bug_type in tool_bugs:
            oyente_injected_bugs = 0
            oyente_bug_FNs = 0
            oyente_miss_classified = 0
            securify_injected_bugs = 0
            securify_bug_FNs = 0
            securify_miss_classified = 0
            mythril_injected_bugs = 0
            mythril_bug_FNs = 0
            mythril_miss_classified = 0
            smartcheck_injected_bugs = 0
            smartcheck_bug_FNs = 0
            smartcheck_miss_classified = 0
            slither_injected_bugs = 0
            slither_bug_FNs = 0
            slither_miss_classified = 0
            crossfuzz_injected_bugs = 0
            crossfuzz_bug_FNs = 0
            crossfuzz_miss_classified = 0
            manticore_injected_bugs = 0
            manticore_bug_FNs = 0
            manticore_miss_classified = 0

            # c = 0

            for contract_order in contract_orders:
                tool_main_dir = os.path.join(main_dir, tool)
                tool_buggy_sc = os.path.join(tool_main_dir, "analyzed_buggy_contracts")
                injected_scs = os.path.join(tool_buggy_sc, bug_type)

                bug_log = injected_scs + "/BugLog_" + str(contract_order) + ".csv"
                buggy_sc = injected_scs + "/buggy_" + str(contract_order) + ".sol"
                result_file = (
                    injected_scs + "/results/buggy_" + str(contract_order) + ".sol.txt"
                )
                if tool in ("Slither", "Oyente"):
                    result_file = (
                        injected_scs
                        + "/results/buggy_"
                        + str(contract_order)
                        + ".sol.json"
                    )
                # if tool in ("CrossFuzz"):
                #     result_file = glob.glob(
                #         injected_scs + f"/results/buggy_{contract_order}.sol.*.json"
                #     )

                # Read the injected bug logs
                with open(bug_log, "r") as result_file_name:
                    reader = csv.reader(result_file_name)
                    bug_log_list = list(reader)

                # Inspect tool reports for false negatives and false positives positives
                if tool == "Securify":
                    detected_bugs = []
                    tool_reported_bugs = []

                    # ""locations of all violation patterns in the tool generated report""
                    violation_pattern = "Violation((.+)\s)+at\s"

                    violation_locs = inject_file.get_pattern_all_offsets(
                        result_file, violation_pattern
                    )
                    for viol in violation_locs:
                        extract_detected_bug(result_file, viol, tool, contract_order)

                    # Inspect flase negatives
                    false_negatives = []
                    miss_classifications = []
                    tool_reported_bugs = [
                        bugs
                        for bugs in tool_reported_bugs
                        if bugs["tool"] == tool and bugs["contract"] == contract_order
                    ]
                    tool_bug_codes = [
                        codes
                        for codes in securify_bug_codes
                        if codes["bug"] == bug_type
                    ]

                    for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                        detected = False
                        miss_classified = False
                        for detected_bug in tool_reported_bugs:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                if (
                                    detected_bug["bugType"].strip()
                                    in tool_bug_codes[0]["codes"]
                                ):
                                    detected = True
                                else:
                                    miss_classified = True
                        if detected == False:
                            false_negatives.append(injected_bug)
                        if miss_classified == True and detected == False:
                            miss_classifications.append(injected_bug)

                    securify_injected_bugs += len(bug_log_list) - 1
                    securify_bug_FNs += len(false_negatives)
                    securify_miss_classified += len(miss_classifications)

                    # Inspect flase positives
                    false_positives = []
                    for detected_bug in tool_reported_bugs:

                        injected = False
                        for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                injected = True
                        if injected == False:
                            reported_non_injected.append(detected_bug)

                elif tool == "Mythril":
                    detected_bugs = []
                    tool_reported_bugs = []

                    # ""locations of all reported bug patterns in the tool generated report""
                    violation_pattern = "===((.+)\s)+--"
                    violation_locs = inject_file.get_pattern_all_offsets(
                        result_file, violation_pattern
                    )
                    for viol in violation_locs:
                        extract_detected_bug(result_file, viol, tool, contract_order)

                    # Inspect flase negatives
                    false_negatives = []
                    miss_classifications = []
                    tool_reported_bugs = [
                        bugs
                        for bugs in tool_reported_bugs
                        if bugs["tool"] == tool and bugs["contract"] == contract_order
                    ]
                    tool_bug_codes = [
                        codes for codes in mythril_bug_codes if codes["bug"] == bug_type
                    ]

                    for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                        detected = False
                        miss_classified = False

                        for detected_bug in tool_reported_bugs:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                if (
                                    detected_bug["bugType"].strip()
                                    in tool_bug_codes[0]["codes"]
                                ):
                                    detected = True
                                else:
                                    miss_classified = True
                        if detected == False:
                            false_negatives.append(injected_bug)
                        if miss_classified == True and detected == False:
                            miss_classifications.append(injected_bug)

                    mythril_injected_bugs += len(bug_log_list) - 1
                    mythril_bug_FNs += len(false_negatives)
                    mythril_miss_classified += len(miss_classifications)

                    # Inspect flase positives
                    for detected_bug in tool_reported_bugs:
                        injected = False
                        for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                injected = True
                        if injected == False:
                            reported_non_injected.append(detected_bug)

                elif tool == "Slither":
                    tool_reported_bugs = []

                    # ""locations of all reported bug patterns in the tool generated report""
                    assert isinstance(result_file, str)

                    with open(result_file) as f:
                        result_errors_dict = json.loads(f.read())
                    violation_locs = get_all_childs(result_errors_dict)

                    # Take all the line that tool report as bug
                    for viol in violation_locs:
                        line = re.findall(r"(?<=sol#)[0-9]*(?=\))", viol["desc"])
                        if len(line) > 0:
                            bugLine = int(line[0])
                        bugType = viol["type"]
                        tool_reported_bugs.append(
                            {
                                "tool": tool,
                                "lines": bugLine,
                                "bugType": bugType,
                                "contract": contract_order,
                            }
                        )

                    # Inspect false negatives
                    false_negatives = []
                    miss_classifications = []
                    tool_reported_bugs = [
                        bugs
                        for bugs in tool_reported_bugs
                        if bugs["tool"] == tool and bugs["contract"] == contract_order
                    ]
                    tool_bug_codes = [
                        codes for codes in slither_bug_codes if codes["bug"] == bug_type
                    ]

                    for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                        detected = False
                        miss_classified = False
                        for detected_bug in tool_reported_bugs:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                if (
                                    detected_bug["bugType"].strip()
                                    in tool_bug_codes[0]["codes"]
                                ):
                                    detected = True
                                else:
                                    miss_classified = True

                        if detected == False:
                            false_negatives.append(injected_bug)
                        if miss_classified == True and detected == False:
                            miss_classifications.append(injected_bug)

                    # print(false_negatives)
                    slither_injected_bugs += len(bug_log_list) - 1
                    slither_bug_FNs += len(false_negatives)
                    slither_miss_classified += len(miss_classifications)

                    # Inspect false positives
                    false_positives = []
                    for detected_bug in tool_reported_bugs:
                        injected = False
                        for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                injected = True
                        if injected == False:
                            reported_non_injected.append(detected_bug)

                elif tool == "CrossFuzz":
                    tool_reported_bugs = []
                    head, tail = os.path.split(buggy_sc)
                    cs_names = [
                        names["names"]
                        for names in contract_names_per_file
                        if names["file"] == tail
                    ]
                    for cs_name in cs_names[0]:
                        result_file = (
                            injected_scs
                            + "/results/buggy_"
                            + str(contract_order)
                            + ".sol."
                            + cs_name
                            + ".json"
                        )
                        if not os.path.isfile(result_file):
                            continue
                        with open(result_file) as f:
                            result_errors_dict: Dict[str, List[Dict]] = json.load(f)[
                                cs_name
                            ]["errors"]
                        for key, crossfuzz_error_list in result_errors_dict.items():
                            for crossfuzz_error in crossfuzz_error_list:
                                tool_reported_bugs.append(
                                    {
                                        "tool": tool,
                                        "lines": crossfuzz_error.get("line", None),
                                        "bugType": crossfuzz_error["type"],
                                        "contract": contract_order,
                                        "contractName": cs_name,
                                    }
                                )
                                
                    # Inspect false negatives
                    false_negatives = []
                    miss_classifications = []
                    tool_reported_bugs = [
                        bugs
                        for bugs in tool_reported_bugs
                        if bugs["tool"] == tool and bugs["contract"] == contract_order
                    ]
                    tool_bug_codes = [
                        codes
                        for codes in crossfuzz_bug_codes
                        if codes["bug"] == bug_type
                    ]

                    for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                        detected = False
                        miss_classified = False
                        for detected_bug in tool_reported_bugs:
                            tool_bug_founded_line_number = (
                                int(detected_bug["lines"])
                                if detected_bug["lines"] is not None
                                else None
                            )

                            if not tool_bug_founded_line_number:
                                continue

                            injected_bug_start_line = int(injected_bug[0])
                            injected_bug_end_line = injected_bug_start_line + int(
                                injected_bug[1]
                            )
                            if (
                                injected_bug_start_line
                                <= tool_bug_founded_line_number
                                < injected_bug_end_line
                            ):
                                if (
                                    detected_bug["bugType"].strip()
                                    in tool_bug_codes[0]["codes"]
                                ):
                                    detected = True
                                else:
                                    miss_classified = True

                        if detected == False:
                            false_negatives.append(injected_bug)
                        if miss_classified == True and detected == False:
                            miss_classifications.append(injected_bug)

                    # print(false_negatives)
                    crossfuzz_injected_bugs += len(bug_log_list) - 1
                    crossfuzz_bug_FNs += len(false_negatives)
                    crossfuzz_miss_classified += len(miss_classifications)

                    # Inspect false positives
                    false_positives = []
                    for detected_bug in tool_reported_bugs:
                        injected = False

                        for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                            tool_bug_founded_line_number = (
                                int(detected_bug["lines"])
                                if detected_bug["lines"] is not None
                                else None
                            )

                            if not tool_bug_founded_line_number:
                                continue

                            injected_bug_start_line = int(injected_bug[0])
                            injected_bug_end_line = injected_bug_start_line + int(
                                injected_bug[1]
                            )
                            if (
                                injected_bug_start_line
                                <= tool_bug_founded_line_number
                                < injected_bug_end_line
                            ):
                                injected = True

                        if injected == False:
                            reported_non_injected.append(detected_bug)

                    # assert isinstance(result_file, list)
                    # for crossfuzz_result_file in result_file:
                    #     # ""locations of all reported bug patterns in the tool generated report""
                    #     crossfuzz_result_filepath, crossfuzz_result_filename = (
                    #         os.path.split(crossfuzz_result_file)
                    #     )
                    #     contract_name = crossfuzz_result_filename.split(".")[2]
                    #     with open(crossfuzz_result_file) as f:
                    #         result_errors_dict: Dict[str, List[Dict]] = json.load(f)[
                    #             contract_name
                    #         ]["errors"]

                    #     # Take all the line that tool report as bug
                    #     for key, crossfuzz_error_list in result_errors_dict.items():
                    #         for crossfuzz_error in crossfuzz_error_list:
                    #             tool_reported_bugs.append(
                    #                 {
                    #                     "tool": tool,
                    #                     "lines": crossfuzz_error.get("line", None),
                    #                     "bugType": crossfuzz_error["type"],
                    #                     "contract": contract_order,
                    #                     "contractName": contract_name,
                    #                 }
                    #             )

                    #     # Inspect false negatives
                    #     false_negatives = []
                    #     miss_classifications = []
                    #     tool_reported_bugs = [
                    #         bugs
                    #         for bugs in tool_reported_bugs
                    #         if bugs["tool"] == tool
                    #         and bugs["contract"] == contract_order
                    #     ]
                    #     tool_bug_codes = [
                    #         codes
                    #         for codes in crossfuzz_bug_codes
                    #         if codes["bug"] == bug_type
                    #     ]

                    #     for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                    #         detected = False
                    #         miss_classified = False
                    #         for detected_bug in tool_reported_bugs:
                    #             tool_bug_founded_line_number = (
                    #                 int(detected_bug["lines"])
                    #                 if detected_bug["lines"] is not None
                    #                 else None
                    #             )

                    #             if not tool_bug_founded_line_number:
                    #                 continue

                    #             injected_bug_start_line = int(injected_bug[0])
                    #             injected_bug_end_line = injected_bug_start_line + int(
                    #                 injected_bug[1]
                    #             )
                    #             if (
                    #                 injected_bug_start_line
                    #                 <= tool_bug_founded_line_number
                    #                 < injected_bug_end_line
                    #             ):
                    #                 if (
                    #                     detected_bug["bugType"].strip()
                    #                     in tool_bug_codes[0]["codes"]
                    #                 ):
                    #                     detected = True
                    #                 else:
                    #                     miss_classified = True

                    #         if detected == False:
                    #             false_negatives.append(injected_bug)
                    #         if miss_classified == True and detected == False:
                    #             miss_classifications.append(injected_bug)

                    #     # print(false_negatives)
                    #     crossfuzz_injected_bugs += len(bug_log_list) - 1
                    #     crossfuzz_bug_FNs += len(false_negatives)
                    #     crossfuzz_miss_classified += len(miss_classifications)

                    #     # Inspect false positives
                    #     false_positives = []
                    #     for detected_bug in tool_reported_bugs:
                    #         injected = False

                    #         for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                    #             tool_bug_founded_line_number = (
                    #                 int(detected_bug["lines"])
                    #                 if detected_bug["lines"] is not None
                    #                 else None
                    #             )

                    #             if not tool_bug_founded_line_number:
                    #                 continue

                    #             injected_bug_start_line = int(injected_bug[0])
                    #             injected_bug_end_line = injected_bug_start_line + int(
                    #                 injected_bug[1]
                    #             )
                    #             if (
                    #                 injected_bug_start_line
                    #                 <= tool_bug_founded_line_number
                    #                 < injected_bug_end_line
                    #             ):
                    #                 injected = True

                    #         if injected == False:
                    #             reported_non_injected.append(detected_bug)

                elif tool == "Smartcheck":
                    detected_bugs = []
                    tool_reported_bugs = []

                    # ""locations of all reported bug patterns in the tool generated report""
                    violation_pattern = "ruleId((.+)\s)+line:\s[0-9]*"

                    violation_locs = inject_file.get_pattern_all_offsets(
                        result_file, violation_pattern
                    )

                    for viol in violation_locs:
                        extract_detected_bug(result_file, viol, tool, contract_order)

                    # Inspect flase negatives
                    false_negatives = []
                    miss_classifications = []

                    tool_reported_bugs = [
                        bugs
                        for bugs in tool_reported_bugs
                        if bugs["tool"] == tool and bugs["contract"] == contract_order
                    ]
                    tool_bug_codes = [
                        codes
                        for codes in smartcheck_bug_codes
                        if codes["bug"] == bug_type
                    ]

                    for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                        detected = False
                        miss_classified = False
                        for detected_bug in tool_reported_bugs:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                if (
                                    detected_bug["bugType"].strip()
                                    in tool_bug_codes[0]["codes"]
                                ):
                                    detected = True
                                else:
                                    miss_classified = True

                        if detected == False:
                            false_negatives.append(injected_bug)
                        if miss_classified == True and detected == False:
                            miss_classifications.append(injected_bug)

                    smartcheck_injected_bugs += len(bug_log_list) - 1
                    smartcheck_bug_FNs += len(false_negatives)
                    smartcheck_miss_classified += len(miss_classifications)

                    # Inspect flase positives
                    false_positives = []
                    for detected_bug in tool_reported_bugs:
                        injected = False
                        for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                injected = True
                        if injected == False:
                            reported_non_injected.append(detected_bug)

                elif tool == "Oyente":
                    detected_bugs = []
                    tool_reported_bugs = []
                    head, tail = os.path.split(buggy_sc)

                    # ""locations of all reported bug patterns in the tool generated report""
                    violation_pattern = "(?<=sol:)(.*)(?=\.\\\)"

                    cs_names = [
                        names["names"]
                        for names in contract_names_per_file
                        if names["file"] == tail
                    ]
                    for cs_name in cs_names[0]:
                        result_file = (
                            injected_scs
                            + "/results/buggy_"
                            + str(contract_order)
                            + ".sol:"
                            + cs_name
                            + ".json"
                        )
                        if not os.path.isfile(result_file):
                            continue

                        violation_locs = inject_file.get_pattern_all_offsets(
                            result_file, violation_pattern
                        )
                        for viol in violation_locs:
                            extract_detected_bug(
                                result_file, viol, tool, contract_order
                            )

                    # Inspect flase negatives
                    false_negatives = []
                    miss_classifications = []
                    tool_reported_bugs = [
                        bugs
                        for bugs in tool_reported_bugs
                        if bugs["tool"] == tool and bugs["contract"] == contract_order
                    ]
                    tool_bug_codes = [
                        codes for codes in oyente_bug_codes if codes["bug"] == bug_type
                    ]

                    for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                        detected = False
                        miss_classified = False
                        for detected_bug in tool_reported_bugs:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                if (
                                    detected_bug["bugType"].strip()
                                    in tool_bug_codes[0]["codes"]
                                ):
                                    detected = True
                                else:
                                    miss_classified = True
                        if detected == False:
                            false_negatives.append(injected_bug)
                        if miss_classified == True and detected == False:
                            miss_classifications.append(injected_bug)

                    oyente_injected_bugs += len(bug_log_list) - 1
                    oyente_bug_FNs += len(false_negatives)
                    oyente_miss_classified += len(miss_classifications)

                    # Inspect flase positives
                    false_positives = []
                    for detected_bug in tool_reported_bugs:
                        injected = False
                        for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                injected = True
                        if injected == False:
                            reported_non_injected.append(detected_bug)

                elif tool == "Manticore":
                    detected_bugs = []
                    tool_reported_bugs = []
                    head, tail = os.path.split(buggy_sc)

                    # ""locations of all reported bug patterns in the tool generated report""
                    violation_pattern = "\-((.+)\s)+[0-9]+"

                    cs_names = [
                        names["names"]
                        for names in contract_names_per_file
                        if names["file"] == tail
                    ]
                    for cs_name in cs_names[0]:
                        result_file = (
                            injected_scs
                            + "/results/buggy_"
                            + str(contract_order)
                            + "."
                            + cs_name
                            + ".txt"
                        )
                        if not os.path.isfile(result_file):
                            continue
                        violation_locs = inject_file.get_pattern_all_offsets(
                            result_file, violation_pattern
                        )
                        for viol in violation_locs:
                            extract_detected_bug(
                                result_file, viol, tool, contract_order
                            )

                    # Inspect flase negatives
                    false_negatives = []
                    miss_classifications = []
                    tool_reported_bugs = [
                        bugs
                        for bugs in tool_reported_bugs
                        if bugs["tool"] == tool and bugs["contract"] == contract_order
                    ]
                    tool_bug_codes = [
                        codes
                        for codes in manticore_bug_codes
                        if codes["bug"] == bug_type
                    ]
                    for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                        detected = False
                        miss_classified = False
                        for detected_bug in tool_reported_bugs:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                if (
                                    detected_bug["bugType"].strip()
                                    in tool_bug_codes[0]["codes"]
                                ):
                                    detected = True
                                else:
                                    miss_classified = True
                        if detected == False:
                            false_negatives.append(injected_bug)
                        if miss_classified == True and detected == False:
                            miss_classifications.append(injected_bug)

                    manticore_injected_bugs += len(bug_log_list) - 1
                    manticore_bug_FNs += len(false_negatives)
                    manticore_miss_classified += len(miss_classifications)

                    # Inspect flase positives
                    false_positives = []
                    for detected_bug in tool_reported_bugs:
                        injected = False
                        for injected_bug in bug_log_list[1 : len(bug_log_list)]:
                            if int(detected_bug["lines"]) >= int(
                                injected_bug[0]
                            ) and int(detected_bug["lines"]) < (
                                int(injected_bug[0]) + int(injected_bug[1])
                            ):
                                injected = True
                        if injected == False:
                            reported_non_injected.append(detected_bug)

            # Append False Negative results
            if tool == "Oyente":
                oyente_FNs.append(
                    {
                        "BugType": bug_type,
                        "InjectedBugs": oyente_injected_bugs,
                        "FalseNegatives": oyente_bug_FNs,
                        "MissClassified": oyente_miss_classified,
                        "UnDetected": (oyente_bug_FNs - oyente_miss_classified),
                    }
                )
            elif tool == "Securify":
                securify_FNs.append(
                    {
                        "BugType": bug_type,
                        "InjectedBugs": securify_injected_bugs,
                        "FalseNegatives": securify_bug_FNs,
                        "MissClassified": securify_miss_classified,
                        "UnDetected": (securify_bug_FNs - securify_miss_classified),
                    }
                )
            elif tool == "Mythril":
                mythril_FNs.append(
                    {
                        "BugType": bug_type,
                        "InjectedBugs": mythril_injected_bugs,
                        "FalseNegatives": mythril_bug_FNs,
                        "MissClassified": mythril_miss_classified,
                        "UnDetected": (mythril_bug_FNs - mythril_miss_classified),
                    }
                )
            elif tool == "Smartcheck":
                smartcheck_FNs.append(
                    {
                        "BugType": bug_type,
                        "InjectedBugs": smartcheck_injected_bugs,
                        "FalseNegatives": smartcheck_bug_FNs,
                        "MissClassified": smartcheck_miss_classified,
                        "UnDetected": (smartcheck_bug_FNs - smartcheck_miss_classified),
                    }
                )
            elif tool == "Slither":
                slither_FNs.append(
                    {
                        "BugType": bug_type,
                        "InjectedBugs": slither_injected_bugs,
                        "FalseNegatives": slither_bug_FNs,
                        "MissClassified": slither_miss_classified,
                        "UnDetected": (slither_bug_FNs - slither_miss_classified),
                    }
                )
            elif tool == "CrossFuzz":
                crossfuzz_FNs.append(
                    {
                        "BugType": bug_type,
                        "InjectedBugs": crossfuzz_injected_bugs,
                        "FalseNegatives": crossfuzz_bug_FNs,
                        "MissClassified": crossfuzz_miss_classified,
                        "UnDetected": (crossfuzz_bug_FNs - crossfuzz_miss_classified),
                    }
                )
            elif tool == "Manticore":
                manticore_FNs.append(
                    {
                        "BugType": bug_type,
                        "InjectedBugs": manticore_injected_bugs,
                        "FalseNegatives": manticore_bug_FNs,
                        "MissClassified": manticore_miss_classified,
                        "UnDetected": (manticore_bug_FNs - manticore_miss_classified),
                    }
                )

    # Export False negative results
    csv_columns = [
        "BugType",
        "InjectedBugs",
        "FalseNegatives",
        "MissClassified",
        "UnDetected",
    ]
    for tool in tools:
        csv_file = os.path.join("FNs/" + tool + "_FNs.csv")
        os.makedirs("FNs/", exist_ok=True)
        try:
            with open(csv_file, "w") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                if tool == "Oyente":
                    for data in oyente_FNs:
                        writer.writerow(data)
                elif tool == "Securify":
                    for data in securify_FNs:
                        writer.writerow(data)
                elif tool == "Mythril":
                    for data in mythril_FNs:
                        writer.writerow(data)
                elif tool == "Smartcheck":
                    for data in smartcheck_FNs:
                        writer.writerow(data)
                elif tool == "Slither":
                    for data in slither_FNs:
                        writer.writerow(data)
                elif tool == "CrossFuzz":
                    for data in crossfuzz_FNs:
                        writer.writerow(data)
                elif tool == "Manticore":
                    for data in manticore_FNs:
                        writer.writerow(data)
            print(
                "\n************************** "
                + tool
                + " False Negatives *******************\n"
            )
            df = pandas.read_csv(csv_file)
            print(df)
        except IOError:
            print("I/O error")

    # Print to console
    # remove duplicates
    tempList = []
    for bug in reported_non_injected:
        if bug not in tempList:
            tempList.append(bug)
    _reported_non_injected = tempList
    coded_reported_non_injected = []

    # Check majority
    for bug in _reported_non_injected:
        coded_bugType = get_bug_type(bug)
        coded_reported_non_injected.append(
            {
                "lines": bug["lines"],
                "tool": bug["tool"],
                "bugType": coded_bugType,
                "contract": bug["contract"],
            }
        )

    for tool in tools:
        if tool == "Oyente":
            tool_bugs = [bugs["bug"] for bugs in oyente_bug_codes]
            for bug in tool_bugs:
                fp_count = 0
                excluded = 0
                other_count = 0
                bug_type_threshold = [
                    thr["threshold"] for thr in thresholds if thr["bug"] == bug
                ][0]
                for sc in contract_orders:
                    type_specific_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] == bug
                        and bugs["contract"] == sc
                    ]
                    other_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] not in tool_bugs
                        and bugs["contract"] == sc
                    ]
                    other_count += len(other_bugs)

                    for sbugs in type_specific_bugs:
                        tools_deteced_bug = [
                            bugs
                            for bugs in coded_reported_non_injected
                            if bugs["lines"] == sbugs["lines"]
                            and bugs["bugType"] == bug
                            and bugs["contract"] == sc
                        ]
                        if not len(tools_deteced_bug) >= bug_type_threshold:
                            fp_count += 1
                        else:
                            excluded += 1

                oyente_FPs.append(
                    {
                        "BugType": bug,
                        "FalsePositives": fp_count,
                        "ExcludedByMajority": excluded,
                        "Total": (fp_count + excluded),
                    }
                )
            oyente_FPs.append(
                {
                    "BugType": "Other",
                    "FalsePositives": other_count,
                    "ExcludedByMajority": 0,
                    "Total": other_count,
                }
            )

        elif tool == "Securify":
            tool_bugs = [bugs["bug"] for bugs in securify_bug_codes]
            for bug in tool_bugs:
                fp_count = 0
                excluded = 0
                other_count = 0

                bug_type_threshold = [
                    thr["threshold"] for thr in thresholds if thr["bug"] == bug
                ][0]
                for sc in contract_orders:
                    type_specific_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] == bug
                        and bugs["contract"] == sc
                    ]
                    other_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] not in tool_bugs
                        and bugs["contract"] == sc
                    ]
                    other_count += len(other_bugs)

                    for sbugs in type_specific_bugs:
                        tools_deteced_bug = [
                            bugs
                            for bugs in coded_reported_non_injected
                            if bugs["lines"] == sbugs["lines"]
                            and bugs["bugType"] == bug
                            and bugs["contract"] == sc
                        ]
                        if not len(tools_deteced_bug) >= bug_type_threshold:
                            fp_count += 1
                        else:
                            excluded += 1

                securify_FPs.append(
                    {
                        "BugType": bug,
                        "FalsePositives": fp_count,
                        "ExcludedByMajority": excluded,
                        "Total": (fp_count + excluded),
                    }
                )
            securify_FPs.append(
                {
                    "BugType": "Other",
                    "FalsePositives": other_count,
                    "ExcludedByMajority": 0,
                    "Total": other_count,
                }
            )

        elif tool == "Mythril":
            tool_bugs = [bugs["bug"] for bugs in mythril_bug_codes]
            for bug in tool_bugs:
                fp_count = 0
                excluded = 0
                other_count = 0
                bug_type_threshold = [
                    thr["threshold"] for thr in thresholds if thr["bug"] == bug
                ][0]
                for sc in contract_orders:
                    type_specific_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] == bug
                        and bugs["contract"] == sc
                    ]
                    other_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] not in tool_bugs
                        and bugs["contract"] == sc
                    ]
                    other_count += len(other_bugs)

                    for sbugs in type_specific_bugs:
                        tools_deteced_bug = [
                            bugs
                            for bugs in coded_reported_non_injected
                            if bugs["lines"] == sbugs["lines"]
                            and bugs["bugType"] == bug
                        ]
                        if not len(tools_deteced_bug) >= bug_type_threshold:
                            fp_count += 1
                        else:
                            excluded += 1

                mythril_FPs.append(
                    {
                        "BugType": bug,
                        "FalsePositives": fp_count,
                        "ExcludedByMajority": excluded,
                        "Total": (fp_count + excluded),
                    }
                )
            mythril_FPs.append(
                {
                    "BugType": "Other",
                    "FalsePositives": other_count,
                    "ExcludedByMajority": 0,
                    "Total": other_count,
                }
            )

        elif tool == "Smartcheck":
            tool_bugs = [bugs["bug"] for bugs in smartcheck_bug_codes]
            for bug in tool_bugs:
                fp_count = 0
                excluded = 0
                other_count = 0
                bug_type_threshold = [
                    thr["threshold"] for thr in thresholds if thr["bug"] == bug
                ][0]
                for sc in contract_orders:
                    type_specific_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] == bug
                        and bugs["contract"] == sc
                    ]
                    other_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] not in tool_bugs
                        and bugs["contract"] == sc
                    ]
                    other_count += len(other_bugs)

                    for sbugs in type_specific_bugs:
                        tools_deteced_bug = [
                            bugs
                            for bugs in coded_reported_non_injected
                            if bugs["lines"] == sbugs["lines"]
                            and bugs["bugType"] == bug
                            and bugs["contract"] == sc
                        ]
                        if not len(tools_deteced_bug) >= bug_type_threshold:
                            fp_count += 1
                        else:
                            excluded += 1

                smartcheck_FPs.append(
                    {
                        "BugType": bug,
                        "FalsePositives": fp_count,
                        "ExcludedByMajority": excluded,
                        "Total": (fp_count + excluded),
                    }
                )
            smartcheck_FPs.append(
                {
                    "BugType": "Other",
                    "FalsePositives": other_count,
                    "ExcludedByMajority": 0,
                    "Total": other_count,
                }
            )

        elif tool == "Slither":
            tool_bugs = [bugs["bug"] for bugs in slither_bug_codes]
            for bug in tool_bugs:
                fp_count = 0
                excluded = 0
                other_count = 0
                bug_type_threshold = [
                    thr["threshold"] for thr in thresholds if thr["bug"] == bug
                ][0]
                for sc in contract_orders:
                    type_specific_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] == bug
                        and bugs["contract"] == sc
                    ]
                    other_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] not in tool_bugs
                        and bugs["contract"] == sc
                    ]
                    other_count += len(other_bugs)

                    for sbugs in type_specific_bugs:
                        tools_deteced_bug = [
                            bugs
                            for bugs in coded_reported_non_injected
                            if bugs["lines"] == sbugs["lines"]
                            and bugs["bugType"] == bug
                            and bugs["contract"] == sc
                        ]
                        if not len(tools_deteced_bug) >= bug_type_threshold:
                            fp_count += 1
                        else:
                            excluded += 1

                slither_FPs.append(
                    {
                        "BugType": bug,
                        "FalsePositives": fp_count,
                        "ExcludedByMajority": excluded,
                        "Total": (fp_count + excluded),
                    }
                )
            slither_FPs.append(
                {
                    "BugType": "Other",
                    "FalsePositives": other_count,
                    "ExcludedByMajority": 0,
                    "Total": other_count,
                }
            )

        elif tool == "CrossFuzz":
            tool_bugs = [bugs["bug"] for bugs in crossfuzz_bug_codes]
            for bug in tool_bugs:
                fp_count = 0
                excluded = 0
                other_count = 0
                bug_type_threshold = [
                    thr["threshold"] for thr in thresholds if thr["bug"] == bug
                ][0]
                for sc in contract_orders:
                    type_specific_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] == bug
                        and bugs["contract"] == sc
                    ]
                    other_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] not in tool_bugs
                        and bugs["contract"] == sc
                    ]
                    other_count += len(other_bugs)

                    for sbugs in type_specific_bugs:
                        tools_deteced_bug = [
                            bugs
                            for bugs in coded_reported_non_injected
                            if bugs["lines"] == sbugs["lines"]
                            and bugs["bugType"] == bug
                            and bugs["contract"] == sc
                        ]
                        if not len(tools_deteced_bug) >= bug_type_threshold:
                            fp_count += 1
                        else:
                            excluded += 1

                crossfuzz_FPs.append(
                    {
                        "BugType": bug,
                        "FalsePositives": fp_count,
                        "ExcludedByMajority": excluded,
                        "Total": (fp_count + excluded),
                    }
                )
            crossfuzz_FPs.append(
                {
                    "BugType": "Other",
                    "FalsePositives": other_count,
                    "ExcludedByMajority": 0,
                    "Total": other_count,
                }
            )

        if tool == "Manticore":
            tool_bugs = [bugs["bug"] for bugs in manticore_bug_codes]
            for bug in tool_bugs:
                fp_count = 0
                excluded = 0
                other_count = 0
                bug_type_threshold = [
                    thr["threshold"] for thr in thresholds if thr["bug"] == bug
                ][0]
                for sc in contract_orders:
                    type_specific_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] == bug
                        and bugs["contract"] == sc
                    ]
                    other_bugs = [
                        bugs
                        for bugs in coded_reported_non_injected
                        if bugs["tool"] == tool
                        and bugs["bugType"] not in tool_bugs
                        and bugs["contract"] == sc
                    ]
                    other_count += len(other_bugs)

                    for sbugs in type_specific_bugs:
                        tools_deteced_bug = [
                            bugs
                            for bugs in coded_reported_non_injected
                            if bugs["lines"] == sbugs["lines"]
                            and bugs["bugType"] == bug
                            and bugs["contract"] == sc
                        ]
                        if not len(tools_deteced_bug) >= bug_type_threshold:
                            fp_count += 1
                        else:
                            excluded += 1

                manticore_FPs.append(
                    {
                        "BugType": bug,
                        "FalsePositives": fp_count,
                        "ExcludedByMajority": excluded,
                        "Total": (fp_count + excluded),
                    }
                )
            manticore_FPs.append(
                {
                    "BugType": "Other",
                    "FalsePositives": other_count,
                    "ExcludedByMajority": 0,
                    "Total": other_count,
                }
            )

    # Export False positive results
    csv_columns = ["BugType", "FalsePositives", "ExcludedByMajority", "Total"]
    for tool in tools:
        csv_file = os.path.join("FPs/" + tool + "_FPs.csv")
        os.makedirs("FPs/", exist_ok=True)
        try:
            with open(csv_file, "w") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                if tool == "Oyente":
                    for data in oyente_FPs:
                        writer.writerow(data)
                elif tool == "Securify":
                    for data in securify_FPs:
                        writer.writerow(data)
                elif tool == "Mythril":
                    for data in mythril_FPs:
                        writer.writerow(data)
                elif tool == "Smartcheck":
                    for data in smartcheck_FPs:
                        writer.writerow(data)
                elif tool == "Slither":
                    for data in slither_FPs:
                        writer.writerow(data)
                elif tool == "CrossFuzz":
                    for data in crossfuzz_FPs:
                        writer.writerow(data)
                elif tool == "Manticore":
                    for data in manticore_FPs:
                        writer.writerow(data)
            print(
                "\n************************** "
                + tool
                + " False Positives *******************\n"
            )
            df = pandas.read_csv(csv_file)
            print(df)
        except IOError:
            print("I/O error")


def get_bug_type(bug_info):
    if bug_info["tool"] == "Oyente":
        tool_bugs = [bugs["bug"] for bugs in oyente_bug_codes]
        for bugType in tool_bugs:
            bug_codes = [
                codes["codes"] for codes in oyente_bug_codes if codes["bug"] == bugType
            ]
            if bug_info["bugType"] in bug_codes[0]:
                return bugType

        return bug_info["bugType"]

    elif bug_info["tool"] == "Securify":
        tool_bugs = [bugs["bug"] for bugs in securify_bug_codes]
        for bugType in tool_bugs:
            bug_codes = [
                codes["codes"]
                for codes in securify_bug_codes
                if codes["bug"] == bugType
            ]
            if bug_info["bugType"] in bug_codes[0]:
                return bugType

        return bug_info["bugType"]

    elif bug_info["tool"] == "Mythril":
        tool_bugs = [bugs["bug"] for bugs in mythril_bug_codes]
        for bugType in tool_bugs:
            bug_codes = [
                codes["codes"] for codes in mythril_bug_codes if codes["bug"] == bugType
            ]
            if bug_info["bugType"] in bug_codes[0]:
                return bugType

        return bug_info["bugType"]

    elif bug_info["tool"] == "Smartcheck":
        tool_bugs = [bugs["bug"] for bugs in smartcheck_bug_codes]
        for bugType in tool_bugs:
            bug_codes = [
                codes["codes"]
                for codes in smartcheck_bug_codes
                if codes["bug"] == bugType
            ]
            if bug_info["bugType"] in bug_codes[0]:
                return bugType

        return bug_info["bugType"]

    elif bug_info["tool"] == "Slither":
        tool_bugs = [bugs["bug"] for bugs in slither_bug_codes]
        for bugType in tool_bugs:
            bug_codes = [
                codes["codes"] for codes in slither_bug_codes if codes["bug"] == bugType
            ]
            if bug_info["bugType"] in bug_codes[0]:
                return bugType

        return bug_info["bugType"]

    elif bug_info["tool"] == "CrossFuzz":
        tool_bugs = [bugs["bug"] for bugs in crossfuzz_bug_codes]
        for bugType in tool_bugs:
            bug_codes = [
                codes["codes"]
                for codes in crossfuzz_bug_codes
                if codes["bug"] == bugType
            ]
            if bug_info["bugType"] in bug_codes[0]:
                return bugType

        return bug_info["bugType"]

    elif bug_info["tool"] == "Manticore":
        tool_bugs = [bugs["bug"] for bugs in manticore_bug_codes]
        for bugType in tool_bugs:
            bug_codes = [
                codes["codes"]
                for codes in manticore_bug_codes
                if codes["bug"] == bugType
            ]
            if bug_info["bugType"] in bug_codes[0]:
                return bugType

        return bug_info["bugType"]


def extract_detected_bug(result_file, bug_info, tool, contract):
    global tool_reported_bugs

    if tool == "Securify":
        bugLine = int(
            re.findall(
                r"\(([^()]+)\)",
                inject_file.get_snippet_at_line(
                    result_file,
                    inject_file.get_line_at_offset(result_file, bug_info["eoffset"]),
                ),
            )[0]
        )
        bugType = re.findall(
            r"(?<= for )(.*)(?= in )",
            inject_file.get_snippet_at_line(result_file, bug_info["line"]),
        )[0]

        tool_reported_bugs.append(
            {"tool": tool, "lines": bugLine, "bugType": bugType, "contract": contract}
        )

    elif tool == "Mythril":
        try:
            bugLine = int(
                re.findall(
                    r"sol:(\d+)",
                    inject_file.get_snippet_at_line(
                        result_file,
                        inject_file.get_line_at_offset(result_file, bug_info["eoffset"])
                        + 1,
                    ),
                )[0]
            )
            bugType = re.findall(
                r"(?<== )(.*)(?= =)",
                inject_file.get_snippet_at_line(result_file, int(bug_info["line"])),
            )[0]
            tool_reported_bugs.append(
                {
                    "tool": tool,
                    "lines": bugLine,
                    "bugType": bugType,
                    "contract": contract,
                }
            )
        except IndexError:
            return

    elif tool == "Smartcheck":
        bugLine = int(
            re.findall(
                r"line:\s(\d+)",
                inject_file.get_snippet_at_line(
                    result_file,
                    inject_file.get_line_at_offset(result_file, bug_info["eoffset"]),
                ),
            )[0]
        )
        bugType = re.findall(
            r"(?<=ruleId:\s)(.*)",
            inject_file.get_snippet_at_line(result_file, int(bug_info["line"])),
        )[0]
        tool_reported_bugs.append(
            {"tool": tool, "lines": bugLine, "bugType": bugType, "contract": contract}
        )

    elif tool == "Oyente":
        bugLine = int(
            re.findall(
                r"sol:(\d+)",
                inject_file.get_snippet_at_line(
                    result_file,
                    inject_file.get_line_at_offset(result_file, bug_info["eoffset"]),
                ),
            )[0]
        )

        s = inject_file.get_snippet_at_line(result_file, int(bug_info["line"]))[0:85]
        bugType = re.findall(r"(?<=Warning: )(.*)(?=\.\\)", s)[0]
        tool_reported_bugs.append(
            {"tool": tool, "lines": bugLine, "bugType": bugType, "contract": contract}
        )

    elif tool == "Manticore":
        bugLine = int(
            re.findall(
                r"[0-9]*\s\s\s*",
                inject_file.get_snippet_at_line(
                    result_file,
                    inject_file.get_line_at_offset(result_file, bug_info["eoffset"]),
                ),
            )[1]
        )
        bugType = re.findall(
            r"(?<=-)(.*)(?= -)",
            inject_file.get_snippet_at_line(result_file, int(bug_info["line"])),
        )[0].strip()
        tool_reported_bugs.append(
            {"tool": tool, "lines": bugLine, "bugType": bugType, "contract": contract}
        )


def get_all_childs(file):
    all_childs = []
    descs = extract_values(file, "description")
    types = extract_values(file, "check")

    for i in range(0, len(descs)):
        all_childs.append({"type": types[i], "desc": descs[i]})

    # print (all_childs)
    return all_childs


def extract_values(obj, key):
    # ""Pull all values of specified key""
    arr = []
    results = extract(obj, arr, key)
    return results


def extract(obj, arr, key):
    # ""Recursively search for values of key""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                extract(v, arr, key)
            elif k == key:
                # arr.append(v)
                for k1, v1 in obj.items():
                    if k1 in ("description", "check"):
                        arr.append(v)
    elif isinstance(obj, list):
        for item in obj:
            extract(item, arr, key)
    return arr


if __name__ == "__main__":
    if 1 != len(sys.argv):
        if sys.argv[1] in ("--help", "-h"):
            printUsage(sys.argv[0])

        tools = sys.argv[1].split(",")
        if 3 == len(sys.argv):
            main_dir = sys.argv[2]
        Inspect_results(tools)

    else:
        print("wrong number of parameters")
