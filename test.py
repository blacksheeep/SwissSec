import angr
import os, sys
from Analyser import Analyser

def main(argv):
    if len(argv) < 2:
        return
    a = Analyser(argv[1])
    a.printAllCalledFunctions()

    print(a.getEntryFunction())
    print(a.getListOfAllFunctionsAddresses())
    print(a.getListOfCalledFunctions(a.function_prototypes.kb.functions["add1"]))
    print(a.getListOfFunctionsInMain())
    

if __name__ == "__main__":
    main(sys.argv)