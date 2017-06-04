import binaryninja
from binaryninja.log import log_info
from binaryninja.enums import MediumLevelILOperation as MLOp

def liveness(bv, fun):
    """Register/stackvar liveness.

    Iterates over MLIL in SSA form.

    - pro: stack/register usage abstracted into 'variables'
    - pro: dependency tracking for worklist alg. is already done via SSA
    - con: some instructions get elided as nops for some reason?
    - con: address spaces across all ILs differ slightly
    """
    ssa = fun.medium_level_il.ssa_form
    # Forward branches aren't available on instruction objects, only the block
    # level and via high-level dominator API. Build an instruction-level branch
    # cache to keep instruction iteration simple for the fixpoint function.
    outgoing_branches = {bb.end - 1:[edge.target.start for edge 
                                        in bb.outgoing_edges] 
                         for bb in ssa.basic_blocks}

    # Powerset lattice constructed from the set of live variables, top =
    # everything is live, bottom = nothing is.
    bottom, top = set(), set(fun.vars)
    # This lattice will be mapped over the set of nodes in an MLIL control flow
    # graph. 
    # The result (a "map lattice") is passed through the function "F", which
    # adds information about register reads/writes. A fixpoint is reached once
    # "F" can't add any more information to the lattice. The work list
    # algorithm is used to find the fixpoint efficiently.

    def f(ea, cfg_to_vars):
        # join live variables in dataflow ahead in CFG
        var = set().union(*[cfg_to_vars[next_ea] for next_ea 
                            in outgoing_branches.get(ea, [ea+1])])
        # subtract anything written at current CFG node
        var -= set(ssa[ea].non_ssa_form.vars_written)
        # re-add anything read at current CFG node
        var |= set(ssa[ea].non_ssa_form.vars_read)

        if ssa[ea].operation in [
                MLOp.MLIL_UNDEF, MLOp.MLIL_UNIMPL, MLOp.MLIL_UNIMPL_MEM,
                ## In some cases, calls are covered by vars_Written/vars_read
                ## I *think* that's for supported calling conventions?
                ## anyway, not going to approximate calls
                #MLOp.MLIL_CALL_SSA, MLOp.MLIL_CALL_SSA_UNTYPED, 
            ]:
            var |= top  # do a safe approximation

        # dependencies for current CFG node, in previous dataflow
        deps = [ssa.get_ssa_var_definition(r_v) for r_v in ssa[ea].vars_read]
        # if definition is at None, that means the variable is defined *here*
        deps = [ea for ea in deps if ea != None] 
        
        return var, deps

    # analyze entire CFG for this function, in the MLIL SSA IR
    all_instructions = sum([[i for i in bb] for bb in ssa], [])
    mlil_live_vars = find_fixpoint(f, len(all_instructions), bottom)

    #
    # analysis done, the rest is rendering
    #
    asm_live_vars = {}
    for ssa_ea,vs in enumerate(mlil_live_vars):
        names = {v.name for v in vs}  # strip Binja types down to name strings
        asm_ea = ssa[ssa_ea].address  # map back from function-local address
        if asm_ea not in asm_live_vars:
            asm_live_vars[asm_ea] = names
        else:  # fold multiple IR steps back into one assembly instruction
            asm_live_vars[asm_ea].union(names)
    asm_live_vars = {k: '{'+', '.join(asm_live_vars[k])+'}' 
                     for k in asm_live_vars}
        
    for ea in asm_live_vars:  # scribble over database, why not, there's undo!
        fun.set_comment(ea, asm_live_vars[ea])


def find_fixpoint(f, n, bottom):
    """Unordered work list algorithm for fixpoints on finite lattices.

    This code returns a fixpoint for the monotonic function F over the map
    lattice constructed from a set with cardinality n (likely representing
    nodes in a control flow graph) and a lattice (likely a powerset lattice,
    but maybe not) representing some interesting abstract domain.

    Since this is written in Python, you'll have to use your imagination for
    all the type signatures. Implementation details:

    - X is represented as an indexed list (could be a dict instead, if
      addressing was non-sequential)
    - F(X)->X is implemented as a function f that takes said list as arguments
      and returns a tuple of (value_at_xi, indexes_of_dependencies_in_X)
    - f is F(X) = [f(X) for i in range(|X|)], n is |X|, bottom is set() if it's
      a powerset lattice but potentially something else.
    """
    x = [bottom] * n
    worklist = set(range(n))
    while worklist:
        i = worklist.pop()
        t = x[i].copy()
        x[i], deps = f(i, x)
        if t != x[i]:
            [worklist.add(j) for j in deps]
    return x
