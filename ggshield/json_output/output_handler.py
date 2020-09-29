from typing import Any, List, NamedTuple, Tuple, Union

from ggshield.scan import Commit, File, Result


class Scan(NamedTuple):
    id: str
    results: List[Result]
    source: Union[Commit, File]


class OutputHandler:
    def process_results(
        self, results: List[Result], show_secrets: bool, verbose: bool
    ) -> Tuple[Any, int]:
        raise NotImplementedError()

    def process_scans(self, scan: Scan) -> int:
        raise NotImplementedError()
