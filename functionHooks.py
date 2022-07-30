import angr, claripy
import sys, os
import IPython
import monkeyhex

class HookClass(angr.SimProcedure): 
    def run(self, return_values=None):
        pass

class HookClassAdd(angr.SimProcedure): 
    def run(self, return_values=None, symbolic_return=True):
        return return_values[0]

def test1(p): 
    p.hook_symbol('print1', HookClass())
    p.hook_symbol('print2', HookClass())
    p.unhook_symbol('print2')

    state = p.factory.entry_state()
    simgr = p.factory.simgr(state)
    simgr.run()

    print(simgr.deadended[0].posix.dumps(1))

    IPython.embed()


def test2(p): 
    p.hook_symbol('add1', HookClassAdd(return_values=[27]))
    p.hook_symbol('add', HookClassAdd())

    p.unhook_symbol('add')

    state = p.factory.entry_state()
    simgr = p.factory.simgr(state)
    simgr.run()

    print(simgr.deadended[0].posix.dumps(1))

    IPython.embed()

def getEntryFunction(project: angr.Project):
    cfg = project.analyses.CFGFast()
    entry_func = cfg.kb.functions[project.entry]
    return entry_func

def getListOfFunctionsInMain(project: angr.Project):
    entry_func = getEntryFunction(project)
    functions = entry_func.functions_called()
    return functions

class Hook1(angr.SimProcedure):

    def run(self):
        print("add1 hooked")
        self.state.regs.rax = claripy.BVS("ret1", 32)	
        print(self.state.regs.rax)

def test3(p):
    functions = getListOfFunctionsInMain(p)
    print(functions)
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    a = functions.pop()
    print(a.name, a.addr)
    p.hook(a.addr, hook=Hook1(), length=5)

    #s = p.analyses.CallingConvention(a, cfg=cfg, analyze_callsites=True)
    s = p.analyses.CallingConvention(a, analyze_callsites=True)
    print ("Analysed function header: ", s.prototype, "Size of ret:", s.prototype.returnty.with_arch(p.arch).size)
    s.prototype

    state = p.factory.full_init_state()
    simgr = p.factory.simgr(state)
    simgr.run()

    print(simgr.stashes)
    print(simgr.deadended[0].posix.dumps(1))

    IPython.embed()
    

def main(argv): 
    if len(argv) < 2:
        return
    prog_name = argv[1]
    p = angr.Project(prog_name, auto_load_libs=False)
    test3(p)



if __name__ == '__main__':
    main(sys.argv)