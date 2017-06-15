import binaryninja
from binaryninja.enums import LowLevelILOperation
import math

def functions(bv, _fun):
    table = sorted([_info(bv, fun) for fun in bv.functions], reverse=True)
    table = [FORMAT % info for _interest, info in table]
    report = '%d functions total.\n\n' % (len(bv.functions),) 
    report += HEADER + ''.join(table)
    bv.show_markdown_report('Interesting Functions', report)
    
HEADER = '| Name | #Xr | #BB | #Br | #Stk | #I | Hint |\n'
HEADER +='|-----:|:--:|:-:|:--:|:--:|:----|------|\n'
FORMAT = '| %s | **%d** | %d | %d | %d | %d | %s |\n'

def _info(bv, fun):
    refs_in = len(bv.get_code_refs(fun.start))
    instructions = sum(map(len, fun.basic_blocks))
    interest = float(refs_in) / max(1, instructions)
    if fun.name == 'sub_' + hex(int(fun.start))[2:]:
        interest *= 1e4
    hint = ''
    if instructions == 1:
        op = fun.low_level_il[0].postfix_operands[-1].operation
        if op == LowLevelILOperation.LLIL_RET:
            hint = 'ret-stub'
    info = (fun.name, 
            refs_in,
            len(fun.basic_blocks),
            len(fun.indirect_branches),
            len(fun.stack_layout),
            instructions,
            hint,
            )
    return interest, info
    

