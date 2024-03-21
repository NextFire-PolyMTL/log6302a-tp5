from collections import defaultdict
from collections.abc import Iterable
from typing import NamedTuple

from code_analysis import CFG
from pydantic import BaseModel


class Pair(NamedTuple):
    def_nid: int
    ref_nid: int


class Taint(BaseModel):
    defs: list[int]
    refs: list[int]
    pairs: list[Pair]
    sinks: list[int]
    filters: list[int]
    safes: list[int]
    sources: list[int]


def get_key(cfg: CFG, nid: int) -> tuple[str, str]:
    return (cfg.get_var_scope(nid), cfg.get_var_id(nid))


class PossiblyTaintedDefinition:
    def __init__(self):
        self.cfg: CFG
        self.taint: Taint

        self.in_dict: dict[int, set[int]]
        self.out_dict: dict[int, set[int]]

        self.gen_dict: dict[int, set[int]]
        self.kill_dict: dict[int, set[int]]

        self.visited: set[int]
        self.worklist: list[int]

    def get_gen(self, nid: int) -> set[int]:
        gen_set = set()
        for nid in self.taint.sinks:
            for definition, reference in self.taint.pairs:
                if reference == nid and definition in self.in_dict[nid]:
                    gen_set.add(definition)
        for nid in self.taint.sources:
            gen_set.add(nid)
        return gen_set

    def get_kill(self, nid: int) -> set[int]:
        kill_set = set()
        if nid in self.taint.defs:
            nid_key = get_key(self.cfg, nid)
            for other_nid in self.taint.defs:
                other_nid_key = get_key(self.cfg, other_nid)
                if nid_key == other_nid_key:
                    kill_set.add(other_nid)
        return kill_set

    def pre_loop_init(self) -> Iterable[None]:
        for entry_nid in self.get_entry_node():
            self.in_dict[entry_nid] = set()
            self.visited.add(entry_nid)
            self.worklist.append(entry_nid)
            yield

    def get_entry_node(self) -> Iterable[int]:
        node_ids = self.cfg.get_node_ids()
        for nid in node_ids:
            if self.cfg.get_type(nid) == "Entry":
                yield nid

    def apply_flow_eq(self, nid: int) -> None:
        self.out_dict[nid] = self.get_gen(nid) | (
            self.in_dict[nid] - self.get_kill(nid)
        )

    def next_nodes(self, nid: int) -> Iterable[int]:
        return self.cfg.get_any_children(nid)

    def can_propagate(self, nid: int, next_nid: int) -> bool:
        return (self.out_dict[nid] - self.in_dict[next_nid]) != set()

    def propagate(self, nid: int, next_nid: int) -> None:
        self.in_dict[next_nid] |= self.out_dict[nid]

    def __call__(
        self, cfg: CFG, taint: Taint
    ) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
        self.cfg = cfg
        self.taint = taint

        self.in_dict = defaultdict(set)
        self.out_dict = defaultdict(set)

        self.visited = set()
        self.worklist = []
        for _ in self.pre_loop_init():
            while self.worklist:
                nid = self.worklist.pop()
                self.apply_flow_eq(nid)
                for next_nid in self.next_nodes(nid):
                    if next_nid not in self.visited or self.can_propagate(
                        nid, next_nid
                    ):
                        self.propagate(nid, next_nid)
                        self.worklist.append(next_nid)
                        self.visited.add(next_nid)

        return self.in_dict, self.out_dict
