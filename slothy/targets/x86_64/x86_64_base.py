from enum import Enum
from slothy.helper import lookup_multidict
from slothy.targets.x86_64.x86_64 import (
    find_class,
    X86Instruction,
)

issue_rate = 4


class ExecutionUnit(Enum):
    ALU = 1

    def __repr__(self):
        return self.name


def add_further_constraints(slothy):
    _ = slothy
    pass


def is_secret_tainted(masking_info):
    _ = masking_info
    pass


def has_min_max_objective(config):
    _ = config
    return False


def get_min_max_objective(slothy):
    _ = slothy
    return


execution_units = {
    (X86Instruction): ExecutionUnit.ALU,
}

inverse_throughput = {
    (X86Instruction): 1,
}

default_latencies = {
    (X86Instruction): 1,
}


def get_latency(src, out_idx, dst):
    _ = (out_idx, dst)  # unused for now
    instclass_src = find_class(src)
    return lookup_multidict(default_latencies, src, instclass_src)


def get_units(src):
    instclass_src = find_class(src)
    units = lookup_multidict(execution_units, src, instclass_src)
    if isinstance(units, list):
        return units
    return [units]


def get_inverse_throughput(src):
    instclass_src = find_class(src)
    return lookup_multidict(inverse_throughput, src, instclass_src)
