import logging
logging.getLogger('angr').setLevel('CRITICAL') #level: WARNING, INFO, NOTSET, DEBUG, ERROR, CRITICAL

import angr, claripy

class Analyszer_Hook(angr.SimProcedure):

    #def __init__(self):
    #    counter = 0

    def run(self):
        pass
        #self.state.regs.rax = claripy.BVS("ret1", 32)