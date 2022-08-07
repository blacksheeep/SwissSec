import logging
logging.getLogger('angr').setLevel('CRITICAL') #level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL

import angr, claripy

class Analyzer: 

    def __init__(self, prog_name: str, auto_load_libs=False, analyze_uncalled=False):
        self.project = angr.Project(prog_name, auto_load_libs=auto_load_libs)
        self.analyze_uncalled = analyze_uncalled #todo if enabled also analyse uncalled functions for weaknesses
        self.cfg = self.project.analyses.CFGFast()
        self.function_prototypes = self.project.analyses.CompleteCallingConventions(recover_variables=True,
                                                                                    force=True, cfg=self.cfg, 
                                                                                    analyze_callsites=True)

    def getListOfFunctionsInMain(self):
        entry_func = self.getEntryFunction()
        functions = entry_func.functions_called()
        return functions

    def getListOfCalledFunctions(self, function: angr.knowledge_plugins.functions.function.Function): 
        functions = function.functions_called()
        return functions

    def getListOfAllFunctionsAddresses(self):
        functionAddresses = list(self.cfg.kb.functions)
        return functionAddresses

    def getEntryFunction(self) -> angr.knowledge_plugins.functions.function.Function:
        entry_func = self.cfg.kb.functions[self.project.entry]
        return entry_func

    def printAllCalledFunctions(self, entry: angr.knowledge_plugins.functions.function.Function=None, exclude_sysfunc=False) -> None:
        if entry is None:
            entry = self.getEntryFunction()
        functions =self.getListOfCalledFunctions(entry)
        if len(functions) > 0:
            if(not exclude_sysfunc or (not entry.is_syscall and not entry.is_plt and not entry.is_simprocedure)):
                print(entry.name, "(" + str(hex(entry.addr)) + ")", "--> 0", functions)
        for f in functions: 
            if(exclude_sysfunc):
                if (f.is_syscall or f.is_plt or f.is_simprocedure):
                    continue
            self.printAllCalledFunctions(f, exclude_sysfunc=exclude_sysfunc)

    

class Vulnerability_Analyser:

    def __init__(self, project: angr.Project):
        self.project = project
        self.stack_chk_fail_addr = self.project.loader.find_symbol("__stack_chk_fail").rebased_addr

    def check_unconstrained(self, state: angr.SimState):
        if state.solver.symbolic(state.regs.pc):
            return True
        return False

    def stack_smashing_checker(self, state: angr.SimState) -> bool:
        if state.addr == self.stack_chk_fail_addr:
            return True
        return False


