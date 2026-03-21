from common.OptimizationRunner import OptimizationRunner

import slothy.targets.x86_64.x86_64 as Arch_x86_64
import slothy.targets.x86_64.x86_64_base as Target_x86_64


class Instructions(OptimizationRunner):
    def __init__(self, var="", arch=Arch_x86_64, target=Target_x86_64):
        _ = var
        super().__init__("instructions", base_dir="tests", arch=arch, target=target)

    def core(self, slothy):
        slothy.config.allow_useless_instructions = True
        slothy.config.constraints.allow_reordering = False
        slothy.config.variable_size = True
        slothy.config.constraints.stalls_first_attempt = 256
        slothy.optimize(start="start", end="end")


test_instances = [
    Instructions(),
]

if __name__ == "__main__":
    for runner in test_instances:
        try:
            runner.run()
            print(f"  OK  {runner.name}")
        except Exception as e:
            print(f"  FAIL {runner.name}: {e}")
