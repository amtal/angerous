from binaryninja.plugin import PluginCommand
from . import liveness
from . import interesting

PluginCommand.register_for_function("ANG Liveness", 
    "Live variables at current instruction values", liveness.liveness)

# should probably register_for_range, but it looks pretty identical in UI atm
PluginCommand.register_for_function("ANG Overview", 
    "Function table with some sorting", interesting.functions)
