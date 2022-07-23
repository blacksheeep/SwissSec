import angr
import os, sys
import IPython

def main(argv):
    if len(argv) < 2:
        return
    
    prog_name = argv[1]
    project = angr.Project(prog_name, auto_load_libs=False)
    res = getListOfFunctions(project)
    print(res)
    function_addresses = getListOfAllFunctionsAddresses(project)

    print(function_addresses)

    IPython.embed()

    
def getListOfFunctions(project: angr.Project):
    entry_func = getEntryFunction(project)
    functions = entry_func.functions_called()
    return functions

def getListOfCalledFunctions(function: angr.knowledge_plugins.functions.function.Function): 
     functions = function.functions_called()
     return functions

def getListOfAllFunctionsAddresses(project: angr.Project):
    cfg = project.analyses.CFGFast()
    functionAddresses = list(cfg.kb.functions)
    return functionAddresses

def getEntryFunction(project: angr.Project):
    cfg = project.analyses.CFGFast()
    entry_func = cfg.kb.functions[project.entry]
    return entry_func


if __name__ == "__main__":
    main(sys.argv)


     #for f in functionAddresses:
     #     func = cfg.kb.functions[f]
     #     if func.name == "main":
     #         print(func