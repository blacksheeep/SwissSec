import logging
logging.getLogger('angr').setLevel('CRITICAL') #level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL

import angr, claripy

class Analyszer_Hook(angr.SimProcedure):

    #def __init__(self):
    #    counter = 0

    def run(self):
        #print("function hooked")
        print("add1 hooked")
        self.state.regs.rax = claripy.BVS("ret1", 32)	
        print(self.state.regs.rax)