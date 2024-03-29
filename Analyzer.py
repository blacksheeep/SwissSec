import logging
logging.getLogger('angr').setLevel('CRITICAL') #level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL

import IPython

import angr, claripy

from Analyszer_Hook import Analyszer_Hook
from Vulnerability_Analyser import Vulnerability_Analyser

class Analyzer: 

    def __init__(self, prog_name: str, auto_load_libs=False, analyze_uncalled=False):
        self.project = angr.Project(prog_name, auto_load_libs=auto_load_libs, main_opts={'base_addr': 0x400000})
        self.cc = self.project.factory.cc()
        self.analyze_uncalled = analyze_uncalled #todo if enabled also analyse uncalled functions for weaknesses
        self.cfg = self.project.analyses.CFGFast()
        self.function_prototypes = self.project.analyses.CompleteCallingConventions(recover_variables=True,
                                                                                    force=True, cfg=self.cfg, 
                                                                                    analyze_callsites=True)
        self.already_executed = set()
        self.bugs = []
        #TODO, iteratively increase looper
        self.loop_depth = 4
        self.path_limit = 40 #TODO if limiter is active, we need to have a coverage map to understand what was verified
        self.loop_seer = angr.exploration_techniques.LoopSeer(cfg=self.cfg, bound=self.loop_depth)#0, limit_concrete_loops=False)
        self.path_limiter = angr.exploration_techniques.LengthLimiter(self.path_limit)
        self.spiller = angr.exploration_techniques.Spiller()
        self.memory_watcher = angr.exploration_techniques.MemoryWatcher()
        self.dfs = angr.exploration_techniques.DFS()
        self.threading = angr.exploration_techniques.Threading(threads=8)
        self.namecounter = 0

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

    def printAllCalledFunctions(self, entry: angr.knowledge_plugins.functions.function.Function=None, exclude_sysfunc=True) -> None:
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
            if entry.addr == f.addr: #prevent recursion
                return
            self.printAllCalledFunctions(f, exclude_sysfunc=exclude_sysfunc)

    def runFunctionBasedAnalysis(self, analyzer: Vulnerability_Analyser, entry: angr.knowledge_plugins.functions.function.Function=None, 
                                 exclude_sysfunc=True, stop_at_bug=False):
        if entry is None:
            entry = self.getEntryFunction()
        functions =self.getListOfCalledFunctions(entry)
        if(exclude_sysfunc):
            functions = list(filter(lambda f: not f.is_syscall and not f.is_plt and not f.is_simprocedure, functions))

        for f in functions:
            if entry.addr == f.addr: 
                return None
            bug = self.runFunctionBasedAnalysis(analyzer, entry=f, exclude_sysfunc=exclude_sysfunc)
            if bug and stop_at_bug: 
                return bug

        if entry.addr in self.already_executed:
            return

        #hook functions called by current function
        for f in functions: 
            self.project.hook(f.addr, hook=Analyszer_Hook(), length=5)

        #execute function symbolically
        #print("Prototype", self.function_prototypes.kb.functions[entry.addr].prototype)
        prototype = self.function_prototypes.kb.functions[entry.addr].prototype
        #IPython.embed() # can i get argument register? can i use radare etc 
        #TODO create argument analyzer
        #args=[]
        #for arg in prototype.args:
        #    if type(arg) == angr.sim_type.SimTypeLongLong:
        #        array = claripy.BVS('str' + str(self.namecounter), 50*8)
        #        ptr_arg = angr.PointerWrapper(array, buffer=False) 
        #        args.append(ptr_arg)#claripy.BVS('name' + str(self.namecounter), 64))
        #        self.namecounter += 1

        state = self.project.factory.call_state(entry.addr, cc=self.cc) #, args=args)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        #state.options.add(angr.sim_options.STRICT_PAGE_ACCESS)
        state.options.add(angr.sim_options.SYMBOLIC)
        state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
        simgr = self.project.factory.simgr(state, save_unconstrained=True)#, veritesting=True) # apparently veritesting makes some problems here
        simgr.use_technique(self.loop_seer)
        simgr.use_technique(self.path_limiter)
        #simgr.use_technique(self.spiller) #FIXME leads to crashes 
        simgr.use_technique(self.memory_watcher)
        simgr.use_technique(self.dfs)
        print("----Symbolically execute function:", entry.name, "@", hex(entry.addr))
        ret_sm = simgr.run(until=lambda sm: analyzer.check(sm)) #Fixme, if stop_at_bug false, continue to find all bugs
        self.already_executed.add(entry.addr)
        
        #unhook functions
        for f in functions: 
            self.project.unhook(f.addr)

        bug = analyzer.check(ret_sm)
        if bug:
            print("Found a bug", bug[0])
            self.bugs.append(bug)
            return bug

        return None


    def runAnalysis(analyzer: Vulnerability_Analyser):
        state = self.project.factory.entry_state()
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        #state.options.add(angr.sim_options.STRICT_PAGE_ACCESS)
        state.options.add(angr.sim_options.SYMBOLIC)
        state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
        simgr = self.project.factory.simgr(state, save_unconstrained=True)#, veritesting=True) # apparently veritesting makes some problems here
        simgr.use_technique(self.loop_seer)
        simgr.use_technique(self.path_limiter)
        simgr.use_technique(self.spiller) #FIXME incompatible with memory watcher? 
        simgr.use_technique(self.memory_watcher)
        #simgr.use_technique(self.dfs)
        simgr.use_technique(self.threading)
        ret_sm = simgr.run(until=lambda sm: analyzer.check(sm)) #Fixme, if stop_at_bug false, continue to find all bugs
        self.already_executed.add(entry.addr)

        bug = analyzer.check(ret_sm)
        if bug:
            print("Found a bug", bug[0])
            self.bugs.append(bug)
            return bug

        return None

            