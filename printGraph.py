
import angr
from angrutils import *
import os, sys

def main(argv):
    if len(argv) < 2:
        return
    
    prog_name = argv[1]
    project = angr.Project(prog_name, auto_load_libs=False)
    res = printGraph(project)
    print(res)

    
def printGraph(project: angr.Project):

    cfg = p.analyses.CFGEmulated()
    plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=False, remove_path_terminator=False)


if __name__ == "__main__":
    main(sys.argv)