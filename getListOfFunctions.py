import angr
import os, sys

def main(argv):
    if len(argv) < 2:
        return
    
    prog_name = argv[1]
    project = angr.Project(prog_name, auto_load_libs=False)
    res = getListOfFunctions(project)
    print(res)

    function_addresses = getListOfFunctionsAddresses(p)

    for f in function_addresses:
        func = cfg.kb.functions[f]
        print(func.name)

    
def getListOfFunctions(project: angr.Project):

    cfg = project.analyses.CFGFast()
    entry_func = cfg.kb.functions[project.entry]
    functions = entry_func.functions_called()
    return functions

def getListOfFunctionsAddresses(project: angr.Project):
    cfg = project.analyses.CFGFast()
    functionAddresses = list(cfg.kb.functions)
    return functionAddresses


if __name__ == "__main__":
    main(sys.argv)


     #for f in functionAddresses:
     #     func = cfg.kb.functions[f]
     #     if func.name == "main":
     #         print(func