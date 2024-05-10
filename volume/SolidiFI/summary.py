import glob
import json
import os
from typing import Dict, List, Set


def list_directories(directory: str):
    return [
        os.path.join(directory, d)
        for d in os.listdir(directory)
        if os.path.isdir(os.path.join(directory, d))
    ]


def list_files(directory: str):
    return [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f))
    ]


crossfuzz_cve_bug_type_dirs = list_directories(
    "./tool_results/CrossFuzz/analyzed_buggy_contracts"
)
crossfuzz_result_dirs = [
    os.path.join(d, "results") for d in crossfuzz_cve_bug_type_dirs
]

crossfuzz_bug_type_set = set()
error_quantity_per_file = {}
summary_result = {}

for crossfuzz_result_dir in crossfuzz_result_dirs:
    glob_list = glob.glob(crossfuzz_result_dir + "/*.json")
    assert len(glob_list) == len(list_files(crossfuzz_result_dir))

    cve_bug_type_name = crossfuzz_result_dir.split("/")[-2]
    summary_result[cve_bug_type_name] = {}

    for crossfuzz_result_file in glob_list:

        with open(crossfuzz_result_file, "r") as r_file:
            crossfuzz_result = json.load(r_file)

        crossfuzz_result_filepath, crossfuzz_result_filename = os.path.split(
            crossfuzz_result_file
        )
        contract_name = crossfuzz_result_filename.split(".")[2]
        cve_bug_filename = os.path.join(cve_bug_type_name, crossfuzz_result_filename)

        result_errors_dict: Dict[str, List[Dict]] = crossfuzz_result[contract_name][
            "errors"
        ]

        summary_result[cve_bug_type_name][cve_bug_filename] = {}
        summary_result[cve_bug_type_name][cve_bug_filename]["total_length"] = 0
        summary_result[cve_bug_type_name][cve_bug_filename]["key_list"] = []
        error_quantity_per_file[cve_bug_filename] = 0

        for key, crossfuzz_error_list in result_errors_dict.items():

            picked_error_list = []

            for crossfuzz_error in crossfuzz_error_list:
                crossfuzz_bug_type_set.add((cve_bug_type_name, crossfuzz_error["type"]))
                summary_result[cve_bug_type_name][cve_bug_filename]["total_length"] += 1
                error_quantity_per_file[cve_bug_filename] += 1
                picked_error_list.append(
                    {
                        "type": crossfuzz_error["type"],
                        "line": crossfuzz_error.get("line", None),
                    }
                )

            assert len(crossfuzz_error_list) == len(picked_error_list)

            summary_result[cve_bug_type_name][cve_bug_filename]["key_list"].append(
                {
                    "key": key,
                    "crossfuzz_error_list_length": len(crossfuzz_error_list),
                    "picked_error_list": picked_error_list,
                }
            )


bug_code_set_mapping: Dict[str, Set] = {}
for cve_bug_type_name, crossfuzz_error_type in crossfuzz_bug_type_set:
    if bug_code_set_mapping.get(cve_bug_type_name, None) is None:
        bug_code_set_mapping[cve_bug_type_name] = set()
    bug_code_set_mapping[cve_bug_type_name].add(crossfuzz_error_type)

bug_codes = [
    {"bug": bug, "codes": list(code_set)}
    for bug, code_set in bug_code_set_mapping.items()
]

with open("crossfuzz_buggy_contracts_summary.json", "w") as w_file:
    w_file.write(
        json.dumps(
            {
                "bug_codes": bug_codes,
                "error_quantity_per_file": error_quantity_per_file,
                "summary_result": summary_result,
            },
            indent=2,
        )
    )
