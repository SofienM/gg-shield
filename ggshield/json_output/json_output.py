from typing import Any, Dict, List, Tuple

from pygitguardian.models import PolicyBreak

from ggshield.filter import censor_content, leak_dictionary_by_ignore_sha
from ggshield.scannable import Result
from ggshield.text_utils import Line
from ggshield.utils import Filemode, get_lines_from_content, update_policy_break_matches


def process_results_json(
    results: List[Result], show_secrets: bool, verbose: bool
) -> Tuple[List[Dict[str, Any]], int]:
    flat_results: List[Dict[str, Any]] = []
    if not results:
        return flat_results, 0

    for result in results:
        flat_results.append(result_to_json(result, show_secrets))

    return flat_results, 1


def result_to_json(result: Result, show_secrets: bool) -> Dict[str, Any]:
    result_dict: Dict[str, Any] = {
        "filename": result.filename,
        "mode": result.filemode.name,
        "issues": [],
    }
    content = result.content
    is_patch = result.filemode != Filemode.FILE

    if not show_secrets:
        content = censor_content(result.content, result.scan.policy_breaks)

    lines = get_lines_from_content(content, result.filemode, is_patch, show_secrets)
    sha_dict = leak_dictionary_by_ignore_sha(result.scan.policy_breaks)

    result_dict["total_issues"] = len(sha_dict)

    for ignore_sha, policy_breaks in sha_dict.items():
        flattened_dict = flattened_policy_break(
            ignore_sha,
            policy_breaks,
            lines,
            is_patch,
        )
        result_dict["issues"].append(flattened_dict)

    return result_dict


def flattened_policy_break(
    ignore_sha: str, policy_breaks: List[PolicyBreak], lines: List[Line], is_patch: bool
) -> Dict[str, Any]:
    flattened_dict: Dict[str, Any] = {
        "matches": [],
        "ignore_sha": ignore_sha,
        "policy": policy_breaks[0].policy,
        "break_type": policy_breaks[0].break_type,
        "occurences": len(policy_breaks),
    }
    for policy_break in policy_breaks:
        update_policy_break_matches(policy_break.matches, lines, is_patch)
        flattened_dict["matches"].extend(policy_break.matches)

    return flattened_dict
