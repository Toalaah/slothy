"""
Partial SLOTHY architecture model for x86_64
"""

import logging
import re
from typing import Any
from enum import Enum
from functools import cache

from unicorn import UC_ARCH_X86, UC_MODE_64

from unicorn.x86_const import (
    UC_X86_REG_AH,
    UC_X86_REG_AL,
    UC_X86_REG_BH,
    UC_X86_REG_BL,
    UC_X86_REG_BP,
    UC_X86_REG_BPL,
    UC_X86_REG_CH,
    UC_X86_REG_CL,
    UC_X86_REG_DH,
    UC_X86_REG_DIL,
    UC_X86_REG_DL,
    UC_X86_REG_R10,
    UC_X86_REG_R10B,
    UC_X86_REG_R11,
    UC_X86_REG_R11B,
    UC_X86_REG_R12,
    UC_X86_REG_R12B,
    UC_X86_REG_R13,
    UC_X86_REG_R13B,
    UC_X86_REG_R14,
    UC_X86_REG_R14B,
    UC_X86_REG_R15,
    UC_X86_REG_R15B,
    UC_X86_REG_R8,
    UC_X86_REG_R8B,
    UC_X86_REG_R9,
    UC_X86_REG_R9B,
    UC_X86_REG_RAX,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
    UC_X86_REG_RSP,
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_EDI,
    UC_X86_REG_ESI,
    UC_X86_REG_ESP,
    UC_X86_REG_EBP,
    UC_X86_REG_R8D,
    UC_X86_REG_R9D,
    UC_X86_REG_R10D,
    UC_X86_REG_R11D,
    UC_X86_REG_R12D,
    UC_X86_REG_R13D,
    UC_X86_REG_R14D,
    UC_X86_REG_R15D,
    UC_X86_REG_SIL,
    UC_X86_REG_SP,
    UC_X86_REG_SPL,
)


from slothy.targets.common import FatalParsingException, UnknownInstruction
from slothy.helper import SourceLine

arch_name = "x86_64"

llvm_mca_arch = "x86-64"
llvm_mc_arch = "x86-64"
# Always add aes flag for llvm-mc assembly -- assuming that the user will not
# use aes instructions on CPUs that do not support it
llvm_mc_attr = "aes"

unicorn_arch = UC_ARCH_X86
unicorn_mode = UC_MODE_64


_FLAGS = [
    "CF",
    "PF",
    "AF",
    "ZF",
    "SF",
    "OF",
]
_GPR64 = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rdi",
    "rsi",
    "rsp",
    "rbp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
]
_GPR32 = [
    "eax",
    "ebx",
    "ecx",
    "edx",
    "edi",
    "esi",
    "esp",
    "ebp",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",
]
_GPR8 = [
    "al",
    "ah",
    "bl",
    "bh",
    "cl",
    "ch",
    "dl",
    "dh",
    "dil",
    "sil",
    "spl",
    "sp",
    "bpl",
    "bp",
    "r8b",
    "r9b",
    "r10b",
    "r11b",
    "r12b",
    "r13b",
    "r14b",
    "r15b",
]
_ALL_GPRS = set(_GPR64 + _GPR32 + _GPR8)

_ALL_GPRS_SORTED = list(sorted(set(_ALL_GPRS), key=len, reverse=True))


class RegisterType(Enum):
    GPR = 1
    FLAGS = 2
    HINT = 3

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    @staticmethod
    @cache
    def spillable(reg_type):
        return reg_type in [RegisterType.GPR]

    @staticmethod
    @cache
    def callee_saved_registers():
        regs = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
        assert all([reg in _ALL_GPRS for reg in regs])
        return regs

    @staticmethod
    def unicorn_link_register():
        raise Exception("x86_64, no link register!")

    @staticmethod
    def unicorn_stack_pointer():
        return UC_X86_REG_RSP

    @staticmethod
    def unicorn_program_counter():
        return UC_X86_REG_RIP

    @staticmethod
    @cache
    def unicorn_reg_by_name(reg):
        """Converts string name of register into numerical identifiers used
        within the unicorn engine"""
        d = {
            # QW registers.
            "rax": UC_X86_REG_RAX,
            "rbx": UC_X86_REG_RBX,
            "rcx": UC_X86_REG_RCX,
            "rdx": UC_X86_REG_RDX,
            "rdi": UC_X86_REG_RDI,
            "rsi": UC_X86_REG_RSI,
            "rsp": UC_X86_REG_RSP,
            "rbp": UC_X86_REG_RBP,
            "r8": UC_X86_REG_R8,
            "r9": UC_X86_REG_R9,
            "r10": UC_X86_REG_R10,
            "r11": UC_X86_REG_R11,
            "r12": UC_X86_REG_R12,
            "r13": UC_X86_REG_R13,
            "r14": UC_X86_REG_R14,
            "r15": UC_X86_REG_R15,
            # DW registers.
            "eax": UC_X86_REG_EAX,
            "ebx": UC_X86_REG_EBX,
            "ecx": UC_X86_REG_ECX,
            "edx": UC_X86_REG_EDX,
            "edi": UC_X86_REG_EDI,
            "esi": UC_X86_REG_ESI,
            "esp": UC_X86_REG_ESP,
            "ebp": UC_X86_REG_EBP,
            "r8d": UC_X86_REG_R8D,
            "r9d": UC_X86_REG_R9D,
            "r10d": UC_X86_REG_R10D,
            "r11d": UC_X86_REG_R11D,
            "r12d": UC_X86_REG_R12D,
            "r13d": UC_X86_REG_R13D,
            "r14d": UC_X86_REG_R14D,
            "r15d": UC_X86_REG_R15D,
            # Byte registers.
            "al": UC_X86_REG_AL,
            "ah": UC_X86_REG_AH,
            "bl": UC_X86_REG_BL,
            "bh": UC_X86_REG_BH,
            "cl": UC_X86_REG_CL,
            "ch": UC_X86_REG_CH,
            "dl": UC_X86_REG_DL,
            "dh": UC_X86_REG_DH,
            "dil": UC_X86_REG_DIL,
            "sil": UC_X86_REG_SIL,
            "spl": UC_X86_REG_SPL,
            "sp": UC_X86_REG_SP,
            "bpl": UC_X86_REG_BPL,
            "bp": UC_X86_REG_BP,
            "r8b": UC_X86_REG_R8B,
            "r9b": UC_X86_REG_R9B,
            "r10b": UC_X86_REG_R10B,
            "r11b": UC_X86_REG_R11B,
            "r12b": UC_X86_REG_R12B,
            "r13b": UC_X86_REG_R13B,
            "r14b": UC_X86_REG_R14B,
            "r15b": UC_X86_REG_R15B,
        }
        return d.get(reg.lower())

    @cache
    def list_registers(
        reg_type, only_extra=False, only_normal=False, with_variants=False
    ):
        gprs = _GPR64 + _GPR32 + _GPR8
        hints = (
            [f"t{i}" for i in range(100)]
            + [f"t{i}{j}" for i in range(8) for j in range(8)]
            + [f"t{i}_{j}" for i in range(16) for j in range(16)]
        )
        flags = _FLAGS

        # TODO: add GPR variants (eax, etc.) should probaby not be a gpr?
        # if with_variants:
        #     gprs += gprs_variants
        #     vregs += vregs_variants
        return {
            RegisterType.GPR: gprs,
            RegisterType.HINT: hints,
            RegisterType.FLAGS: flags,
        }[reg_type]

    @staticmethod
    def find_type(r):
        """Find type of architectural register"""

        if r.startswith("hint_"):
            return RegisterType.HINT

        for ty in RegisterType:
            if r in RegisterType.list_registers(ty):
                return ty

        return None

    @staticmethod
    def is_renamed(ty):
        """Indicate if register type should be subject to renaming"""
        if ty == RegisterType.HINT:
            return False
        return True

    @staticmethod
    def from_string(string):
        """Find register type from string"""
        return {
            "gpr": RegisterType.GPR,
            "hint": RegisterType.HINT,
            "flags": RegisterType.FLAGS,
        }.get(string.lower())

    @staticmethod
    def default_reserved():
        """Return the list of registers that should be reserved by default"""
        return set(["flags", "sp"] + RegisterType.list_registers(RegisterType.HINT))

    @staticmethod
    def default_aliases():
        "Register aliases used by the architecture"
        return {}


# TODO: add loop subclasses, see aarch64_neon (BranchLoop, SubsLoop, SubLoop)
class Branch:
    """Helper for emitting branches"""

    @staticmethod
    def if_equal(cnt, val, lbl):
        """Emit assembly for a branch-if-equal sequence"""
        yield f"cmp {cnt}, #{val}"
        yield f"je {lbl}"

    @staticmethod
    def if_greater_equal(cnt, val, lbl):
        """Emit assembly for a branch-if-greater-equal sequence"""
        yield f"cmp {cnt}, #{val}"
        yield f"jge {lbl}"

    @staticmethod
    def unconditional(lbl):
        """Emit unconditional branch"""
        yield f"jmp {lbl}"


class Instruction:

    all_subclass_leaves: list

    class ParsingException(Exception):
        """An attempt to parse an assembly line as a specific instruction failed

        This is a frequently encountered exception since assembly lines are parsed by
        trial and error, iterating over all instruction parsers."""

        def __init__(self, err=None):
            super().__init__(err)

    def __init__(
        self,
        *,
        mnemonic,
        arg_types_in=None,
        arg_types_in_out=None,
        arg_types_out=None,
    ):
        if arg_types_in is None:
            arg_types_in = []
        if arg_types_out is None:
            arg_types_out = []
        if arg_types_in_out is None:
            arg_types_in_out = []

        self.mnemonic = mnemonic

        self.args_out_combinations = None
        self.args_in_combinations = None
        self.args_in_out_combinations = None
        self.args_in_out_different = None
        self.args_in_inout_different = None

        self.arg_types_in = arg_types_in
        self.arg_types_out = arg_types_out
        self.arg_types_in_out = arg_types_in_out
        self.num_in = len(arg_types_in)
        self.num_out = len(arg_types_out)
        self.num_in_out = len(arg_types_in_out)

        self.args_out_restrictions = [None for _ in range(self.num_out)]
        self.args_in_restrictions = [None for _ in range(self.num_in)]
        self.args_in_out_restrictions = [None for _ in range(self.num_in_out)]

        self.args_in = []
        self.args_out = []
        self.args_in_out = []

        self.addr = None
        self.increment = None
        self.pre_index = None
        self.offset_adjustable = True

        self.immediate = None
        self.datatype = None
        self.index = None
        self.flag = None

        # Enables typing for self.source_line in methods below.
        self.source_line: SourceLine

    def extract_read_writes(self):
        # TODO: check this method
        """Extracts 'reads'/'writes' clauses from the source line of the instruction"""

        src_line = self.source_line

        def hint_register_name(tag):
            return f"hint_{tag}"

        # Check if the source line is tagged as reading/writing from memory
        def add_memory_write(tag):
            self.num_out += 1
            self.args_out_restrictions.append(None)
            self.args_out.append(hint_register_name(tag))
            self.arg_types_out.append(RegisterType.HINT)

        def add_memory_read(tag):
            self.num_in += 1
            self.args_in_restrictions.append(None)
            self.args_in.append(hint_register_name(tag))
            self.arg_types_in.append(RegisterType.HINT)

        write_tags = src_line.tags.get("writes", [])
        read_tags = src_line.tags.get("reads", [])

        if not isinstance(write_tags, list):
            write_tags = [write_tags]

        if not isinstance(read_tags, list):
            read_tags = [read_tags]

        for w in write_tags:
            add_memory_write(w)

        for r in read_tags:
            add_memory_read(r)

        return self

    def global_parsing_cb(self, a, log=None):
        """Parsing callback triggered after DataFlowGraph parsing which allows
        modification of the instruction in the context of the overall computation.

        This is primarily used to remodel input-outputs as outputs in jointly destructive
        instruction patterns (See Section 4.4, https://eprint.iacr.org/2022/1303.pdf).
        """
        _ = log  # log is not used
        return False

    def global_fusion_cb(self, a, log=None):
        """Fusion callback triggered after DataFlowGraph parsing which allows fusing
        of the instruction in the context of the overall computation.

        This can be used e.g. to detect eor-eor pairs and replace them by eor3."""
        _ = log  # log is not used
        return False

    def write(self):
        """Write the instruction"""
        args = self.args_out + self.args_in_out + self.args_in
        return self.mnemonic + " " + ", ".join(args)

    @staticmethod
    def unfold_abbrevs(mnemonic):
        return mnemonic

    def _is_instance_of(self, inst_list):
        for inst in inst_list:
            if isinstance(self, inst):
                return True
        return False

    def is_vector_load(self):
        return self._is_instance_of([])

    def is_vector_store(self):
        return self._is_instance_of([])

    # scalar
    def is_scalar_load(self):
        return self._is_instance_of([])

    def is_scalar_store(self):
        return self._is_instance_of([])

    # scalar or vector
    def is_load(self):
        return self.is_vector_load() or self.is_scalar_load()

    def is_store(self):
        return self.is_vector_store() or self.is_scalar_store()

    def is_load_store_instruction(self):
        return self.is_load() or self.is_store()

    def declassifies_output(self, output_idx):
        """Check if this instruction declassifies (produces public value)
        for a given output.

        Returns True if the output at output_idx is guaranteed to be public,
        regardless of input masking.

        Architecture-specific implementations should override this.

        Args:
            output_idx: Index of the output to check

        Returns:
            bool: True if the output is declassified to public
        """
        return False

    @classmethod
    def make(cls, src):
        """Abstract factory method parsing a string into an instruction instance."""

    @staticmethod
    def build(c: Any, src: str, mnemonic: str, **kwargs: list) -> "Instruction":
        if src.split(" ")[0] != mnemonic:
            raise Instruction.ParsingException("Mnemonic does not match")

        obj = c(mnemonic=mnemonic, **kwargs)

        # Replace <dt> by list of all possible datatypes
        mnemonic = Instruction.unfold_abbrevs(obj.mnemonic)

        expected_args = obj.num_in + obj.num_out + obj.num_in_out
        regexp_txt = rf"^\s*{mnemonic}"
        if expected_args > 0:
            regexp_txt += r"\s+"
        regexp_txt += ",".join([r"\s*(\w+)\s*" for _ in range(expected_args)])
        regexp = re.compile(regexp_txt)

        p = regexp.match(src)
        if p is None:
            raise Instruction.ParsingException(
                f"Doesn't match basic instruction template {regexp_txt}"
            )

        operands = list(p.groups())

        if obj.num_out > 0:
            obj.args_out = operands[: obj.num_out]
            idx_args_in = obj.num_out
        elif obj.num_in_out > 0:
            obj.args_in_out = operands[: obj.num_in_out]
            idx_args_in = obj.num_in_out
        else:
            idx_args_in = 0

        obj.args_in = operands[idx_args_in:]

        if not len(obj.args_in) == obj.num_in:
            raise FatalParsingException(
                f"Something wrong parsing {src}: Expect {obj.num_in} input,"
                f" but got {len(obj.args_in)} ({obj.args_in})"
            )

        return obj

    @staticmethod
    def parser(src_line):
        """Global factory method parsing an assembly line into an instance
        of a subclass of Instruction."""
        insts = []
        exceptions = {}
        instnames = []

        src = src_line.text.strip()

        # Iterate through all derived classes and call their parser
        # until one of them hopefully succeeds
        for inst_class in Instruction.all_subclass_leaves:
            try:
                inst = inst_class.make(src)
                instnames = [inst_class.__name__]
                insts = [inst]
                break
            except Instruction.ParsingException as e:
                exceptions[inst_class.__name__] = e

        for i in insts:
            i.source_line = src_line
            i.extract_read_writes()

        if len(insts) == 0:
            logging.error("Failed to parse instruction %s", src)
            logging.error("A list of attempted parsers and their exceptions follows.")
            for i, e in exceptions.items():
                msg = f"* {i + ':':20s} {e}"
                logging.error(msg)
            raise Instruction.ParsingException(
                f"Couldn't parse {src}\nYou may need to add support "
                "for a new instruction (variant)?"
            )

        logging.debug("Parsing result for '%s': %s", src, instnames)
        return insts

    def __repr__(self):
        return self.write()


class X86Instruction(Instruction):
    """Abstract class representing X86_64 instructions"""

    PARSERS = {}

    @staticmethod
    def _replace_duplicate_datatypes(src, mnemonic_key):
        pattern = re.compile(rf"<{re.escape(mnemonic_key)}\d*>")

        matches = list(pattern.finditer(src))

        if len(matches) > 1:
            for i, match in enumerate(reversed(matches)):
                start, end = match.span()
                src = src[:start] + f"<{mnemonic_key}{len(matches)-1-i}>" + src[end:]

        return src

    @staticmethod
    def _unfold_pattern(src):
        # Those replacements may look pointless, but they replace
        # actual whitespaces before/after '.,[]()' in the instruction
        # pattern by regular expressions allowing flexible whitespacing.
        flexible_spacing = [
            (r"\s*,\s*", r"\\s*,\\s*"),
            (r"\s*<imm>\s*", r"\\s*<imm>\\s*"),
            (r"\s*\[\s*", r"\\s*\\[\\s*"),
            (r"\s*\]\s*", r"\\s*\\]\\s*"),
            (r"\s*\(\s*", r"\\s*\\(\\s*"),  # Handle ( for load/store
            (r"\s*\)\s*", r"\\s*\\)\\s*"),  # Handle ) for load/store
            (r"\s*\.\s*", r"\\s*\\.\\s*"),
            (r"\s*\+\+\s*", r"\\s*\\+\\+\\s*"),  # Handle ++ for increment
            (r"\s+", r"\\s+"),
            (r"\\s\*\\s\\+", r"\\s+"),
            (r"\\s\+\\s\\*", r"\\s+"),
            (r"(\\s\*)+", r"\\s*"),
        ]
        for c, cp in flexible_spacing:
            src = re.sub(c, cp, src)

        gpr64_pattern = "|".join(sorted(_GPR64, key=len, reverse=True))

        def pattern_transform_q(g):
            return f"(?P<raw_{g.group(1)}{g.group(2)}>({gpr64_pattern}))"

        # Quadwords (64-bit registers only)
        src = re.sub(r"<([Q])(\w+)>", pattern_transform_q, src)

        # Replace <key> or <key0>, <key1>, ... with pattern
        def replace_placeholders(src, mnemonic_key, regexp, group_name):
            prefix = f"<{mnemonic_key}"
            pattern = f"<{mnemonic_key}>"

            def pattern_i(i):
                return f"<{mnemonic_key}{i}>"

            cnt = src.count(prefix)
            if cnt > 1:
                for i in range(cnt):
                    src = re.sub(pattern_i(i), f"(?P<{group_name}{i}>{regexp})", src)
            else:
                src = re.sub(pattern, f"(?P<{group_name}>{regexp})", src)

            return src

        flag_pattern = "|".join(
            [
                "CF",
                "PF",
                "AF",
                "ZF",
                "SF",
                "OF",
            ]
        )
        imm_pattern = r"(?:0[xX][0-9a-fA-F]+|-?[0-9]+)"
        index_pattern = "[0-9]+"

        src = replace_placeholders(src, "imm", imm_pattern, "imm")
        src = X86Instruction._replace_duplicate_datatypes(src, "dt")
        src = replace_placeholders(src, "index", index_pattern, "index")
        src = replace_placeholders(src, "flag", flag_pattern, "flag")

        src = r"\s*" + src + r"\s*(//.*)?\Z"
        return src

    @staticmethod
    def _build_parser(src):
        regexp_txt = X86Instruction._unfold_pattern(src)
        regexp = re.compile(regexp_txt)

        def _parse(line):
            regexp_result = regexp.match(line)
            if regexp_result is None:
                raise Instruction.ParsingException(
                    f"Does not match instruction pattern {src}" f"[regex: {regexp_txt}]"
                )
            res = regexp.match(line).groupdict()
            items = list(res.items())
            for k, v in items:
                for prefix in ["raw_"]:
                    if k.startswith(prefix):
                        del res[k]
                        if v is None:
                            continue
                        k = k[len(prefix) :]
                        res[k] = v
            return res

        return _parse

    @staticmethod
    def get_parser(pattern):
        if pattern in X86Instruction.PARSERS:
            return X86Instruction.PARSERS[pattern]
        parser = X86Instruction._build_parser(pattern)
        X86Instruction.PARSERS[pattern] = parser
        return parser

    @cache
    def _infer_register_type(ptrn):
        # Then check by prefix
        if ptrn[0].upper() in ["Q"]:
            return RegisterType.GPR
        # if ptrn[0].upper() in ["T"]:
        #     return RegisterType.HINT
        # if ptrn[:2].upper() in ["FG"]:
        #     return RegisterType.FLAGS
        raise FatalParsingException(f"Unknown pattern: {ptrn}")

    def __init__(
        self,
        pattern,
        *,
        inputs=None,
        outputs=None,
        in_outs=None,
    ):

        self.mnemonic = pattern.split(" ")[0]

        if inputs is None:
            inputs = []
        if outputs is None:
            outputs = []
        if in_outs is None:
            in_outs = []

        arg_types_in = [X86Instruction._infer_register_type(r) for r in inputs]
        arg_types_out = [X86Instruction._infer_register_type(r) for r in outputs]
        arg_types_in_out = [X86Instruction._infer_register_type(r) for r in in_outs]

        super().__init__(
            mnemonic=pattern,
            arg_types_in=arg_types_in,
            arg_types_out=arg_types_out,
            arg_types_in_out=arg_types_in_out,
        )

        self.inputs = inputs
        self.outputs = outputs
        self.in_outs = in_outs

        self.pattern = pattern
        assert len(inputs) == len(arg_types_in)
        self.pattern_inputs = list(zip(inputs, arg_types_in))
        assert len(outputs) == len(arg_types_out)
        self.pattern_outputs = list(zip(outputs, arg_types_out))
        assert len(in_outs) == len(arg_types_in_out)
        self.pattern_in_outs = list(zip(in_outs, arg_types_in_out))

    @staticmethod
    def _to_reg(ty, s):
        if ty == RegisterType.GPR:
            c = "x"  # TODO: this is wrong
        elif ty == RegisterType.HINT:
            c = "t"
        elif ty == RegisterType.FLAGS:
            c = "FG"
        else:
            assert False
        if s.replace("_", "").isdigit():
            return f"{c}{s}"
        return s

    @staticmethod
    def _build_pattern_replacement(s, ty, arg):
        if ty == RegisterType.GPR:
            # x86_64 registers are fully named (rax, rsi, r8, etc.), return as-is
            return arg
        if ty == RegisterType.HINT:
            if arg[0] != "t":
                return f"{s[0].upper()}<{arg}>"
            return arg
        if ty == RegisterType.FLAGS:
            if arg[:2] != "FG":
                return f"{s[0].upper()}<{arg}>"
            return s[0].upper() + arg[1:]
        raise FatalParsingException(f"Unknown register type ({s}, {ty}, {arg})")

    @staticmethod
    def _instantiate_pattern(s, ty, arg, out):
        if ty == RegisterType.FLAGS:
            return out
        rep = X86Instruction._build_pattern_replacement(s, ty, arg)
        res = out.replace(f"<{s}>", rep)
        # if res == out:
        #     raise FatalParsingException(
        #         f"Failed to replace <{s}> by {rep} in {out} (have {res})!"
        #     )
        return res

    @staticmethod
    def build_core(obj, res):

        def group_to_attribute(group_name, attr_name, f=None):
            def f_default(x):
                return x

            def group_name_i(i):
                return f"{group_name}{i}"

            if f is None:
                f = f_default
            if group_name in res.keys():
                setattr(obj, attr_name, f(res[group_name]))
            else:
                idxs = [i for i in range(4) if group_name_i(i) in res.keys()]
                if len(idxs) == 0:
                    return
                assert idxs == list(range(len(idxs)))
                setattr(
                    obj, attr_name, list(map(lambda i: f(res[group_name_i(i)]), idxs))
                )

        group_to_attribute("datatype", "datatype", lambda x: x.lower())
        group_to_attribute(
            "imm", "immediate", lambda x: x.replace("#", "")
        )  # Strip '#'
        group_to_attribute("index", "index", int)
        group_to_attribute("flag", "flag")

        for s, ty in obj.pattern_inputs:
            if ty == RegisterType.FLAGS and s in ["FG0", "FG1"]:
                # Implicit FLAGS registers (FG0, FG1) - not in pattern
                obj.args_in.append(s)
            else:
                obj.args_in.append(X86Instruction._to_reg(ty, res[s]))
        for s, ty in obj.pattern_outputs:
            if ty == RegisterType.FLAGS and s in ["FG0", "FG1"]:
                # Implicit FLAGS registers (FG0, FG1) - not in pattern
                obj.args_out.append(s)
            else:
                obj.args_out.append(X86Instruction._to_reg(ty, res[s]))

        for s, ty in obj.pattern_in_outs:
            if ty == RegisterType.FLAGS and s in ["FG0", "FG1"]:
                # Implicit FLAGS registers (FG0, FG1) - not in pattern
                obj.args_in_out.append(s)
            else:
                obj.args_in_out.append(X86Instruction._to_reg(ty, res[s]))

    @staticmethod
    def build(c, src):
        pattern = getattr(c, "pattern")
        inputs = getattr(c, "inputs", []).copy()
        outputs = getattr(c, "outputs", []).copy()
        in_outs = getattr(c, "in_outs", []).copy()

        if isinstance(src, str):
            if src.split(" ")[0] != pattern.split(" ")[0]:
                raise Instruction.ParsingException("Mnemonic does not match")
            res = X86Instruction.get_parser(pattern)(src)
        else:
            assert isinstance(src, dict)
            res = src

        obj = c(
            pattern,
            inputs=inputs,
            outputs=outputs,
            in_outs=in_outs,
        )

        X86Instruction.build_core(obj, res)
        return obj

    @classmethod
    def make(cls, src):
        return X86Instruction.build(cls, src)

    def write(self):
        out = self.pattern
        ll = (
            list(zip(self.args_in, self.pattern_inputs))
            + list(zip(self.args_out, self.pattern_outputs))
            + list(zip(self.args_in_out, self.pattern_in_outs))
        )

        for arg, (s, ty) in ll:
            out = X86Instruction._instantiate_pattern(s, ty, arg, out)

        def replace_pattern(txt, attr_name, mnemonic_key, t=None):
            def t_default(x):
                return x

            if t is None:
                t = t_default

            a = getattr(self, attr_name)
            if a is None:
                return txt
            if not isinstance(a, list):
                txt = txt.replace(f"<{mnemonic_key}>", t(a))
                return txt
            for i, v in enumerate(a):
                txt = txt.replace(f"<{mnemonic_key}{i}>", t(v))
            return txt

        out = replace_pattern(out, "immediate", "imm", lambda x: x)
        out = X86Instruction._replace_duplicate_datatypes(out, "dt")
        out = replace_pattern(out, "flag", "flag")
        out = replace_pattern(out, "index", "index", str)

        out = out.replace("\\[", "[")
        out = out.replace("\\]", "]")
        out = out.replace("\\(", "(")
        out = out.replace("\\)", ")")
        return out


# Instructions


# class nop(X86Instruction):
#     pattern = "nop"


class add(X86Instruction):
    pattern = "add <Qa>, <Qb>"
    in_outs = ["Qa"]
    inputs = ["Qb"]
    modifiesFlags = True


# class add_imm(X86Instruction):
#     pattern = "add <Qa>, <imm>"
#     inputs = ["Qa"]
#     outputs = ["Qa"]
#     modifiesFlags = True


def iter_x86_64_instructions():
    yield from all_subclass_leaves(Instruction)


def find_class(src):
    for inst_class in iter_x86_64_instructions():
        if isinstance(src, inst_class):
            return inst_class
    raise UnknownInstruction(
        f"Couldn't find instruction class for {src} (type {type(src)})"
    )


def all_subclass_leaves(c):

    def has_subclasses(cl):
        return len(cl.__subclasses__()) > 0

    def is_leaf(c):
        return not has_subclasses(c)

    def all_subclass_leaves_core(leaf_lst, todo_lst):
        leaf_lst += filter(is_leaf, todo_lst)
        todo_lst = [
            csub
            for c in filter(has_subclasses, todo_lst)
            for csub in c.__subclasses__()
        ]
        if len(todo_lst) == 0:
            return leaf_lst
        return all_subclass_leaves_core(leaf_lst, todo_lst)

    return all_subclass_leaves_core([], [c])


Instruction.all_subclass_leaves = all_subclass_leaves(Instruction)
