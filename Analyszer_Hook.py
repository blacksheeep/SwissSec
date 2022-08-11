import logging
logging.getLogger('angr').setLevel('CRITICAL') #level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL

import angr, claripy

class Analyszer_Hook(angr.SimProcedure):

    #def __init__(self):
    #    counter = 0

    def run(self):
        print("function hooked")
        #self.state.regs.rax = claripy.BVS("ret", 64)	
        #Analyszer_Hook.counter = Analyszer_Hook.counter+1
        print(self.state.regs.rax)