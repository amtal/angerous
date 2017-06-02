from binaryninja.plugin import PluginCommand
from . import liveness

PluginCommand.register_for_function("Angerous Liveness", 
    "Live variables at current instruction values", liveness.liveness)
