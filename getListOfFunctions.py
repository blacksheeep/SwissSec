import angr
import os, sys

def main(argv):
    if len(argv) < 2:
        return
    
    prog_name = argv[1]
    project = angr.Project(prog_name, auto_load_libs=False)
    res = getListOfFunctions(project)
    print(res)

    
def getListOfFunctions(project: angr.Project):

    cfg = project.analyses.CFGFast()
    entry_func = cfg.kb.functions[project.entry]
    functions = entry_func.functions_called()
    return functions


if __name__ == "__main__":
    main(sys.argv)