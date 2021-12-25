import angr
import os, sys

def main(argv):
    if len(argv) < 2:
        return
    
    prog_name = argv[1]
    
    project = angr.Project(prog_name, auto_load_libs=False)

    show_functions(project)
    
def show_functions(project: angr.Project):

    cfg = project.analyses.CFGFast()
    print(project.kb.functions.items())



if __name__ == "__main__":
    main(sys.argv)