import sys
import numpy as np
import itertools
import matplotlib.pyplot as plt
from threading import Thread
from collections import Counter
from functools import lru_cache

class ThreadWithReturnValue(Thread):
	def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
		Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)
		print(f"[DFA] Starting thread for target {args[1]}.")
		self._return = None

	def run(self):
		if self._target is not None:
			self._return = self._target(*self._args, **self._kwargs)

	def join(self):
		Thread.join(self)
		return self._return

sbox = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
], dtype=np.uint8)

vhex = np.vectorize(hex)

def GenerateEOUTMatrix(patterns,xorfaults):
	matrix=[[],[],[],[]]
	for num, pattern in enumerate(patterns):
		for fault in xorfaults:
			if np.all((pattern^(fault!=0)==0)):
				matrix[num].append(fault)
	return matrix

@lru_cache(maxsize=4096)
def pmul(p1, p2):
    res = 0
    for i in range(8):
        if p2 & 1:
            res ^= p1
        hi_bit_set = p1 & 0x80
        p1 <<= 1
        p1 &= 0xFF
        if hi_bit_set:
            p1 ^= 0x1b
        p2 >>= 1
    return res

def ForceCandidates(traces,target,multipliers,limit):
	candidates=[]
	for trace in traces:
		for error in range(256):
			for b1 in range(256):
				if LeftFormula(b1,error,multipliers[0])==RightFormula(b1,trace[target[0]]):				
					for b2 in range(256):
						if LeftFormula(b2,error,multipliers[1])==RightFormula(b2,trace[target[1]]):
							for b3 in range(256):
								if LeftFormula(b3,error,multipliers[2])==RightFormula(b3,trace[target[2]]):
									for b4 in range(256):
										if LeftFormula(b4,error,multipliers[3])==RightFormula(b4,trace[target[3]]):
											candidates.append([b1,b2,b3,b4])
											if limit!=0 and len(candidates)>=limit:
												return candidates
	return candidates

def FindAllCandidates(matrix,limit):
	threadPool=[]
	allCandidates=[[], [], [], []]
	target=[[(0,0),(1,3),(2,2),(3,1)],[(0,1),(1,0),(2,3),(3,2)],[(0,2),(1,1),(2,0),(3,3)],[(0,3),(1,2),(2,1),(3,0)]]
	multipliers=[[2,1,1,3],[3,2,1,1],[1,3,2,1],[1,1,3,2]]
	for i in range(len(matrix)):
		thread=ThreadWithReturnValue(target=ForceCandidates, args=[matrix[i],target[i],multipliers[i],limit])
		thread.start()
		threadPool.append(thread)
	for y in range(len(threadPool)):
		result=threadPool[y].join()
		for candidate in result:
			allCandidates[y].append(candidate)
	return allCandidates

def GetSubKey10(allCandidates,original):
	subKey0=[]
	for candidates in allCandidates:
		tally=Counter(list(map(tuple,candidates)))
		x=max(tally, key=tally.get)
		subKey0.append(x)
	subKey0=np.array(subKey0).T
	subKey0=ShiftRows(SubBytes(subKey0))^original
	return subKey0

def Round2MasterKey(key):
	rcons=[[0x36,0x00,0x00,0x00],[0x1B,0x00,0x00,0x00],[0x80,0x00,0x00,0x00],[0x40,0x00,0x00,0x00],
	[0x20,0x00,0x00,0x00],[0x10,0x00,0x00,0x00],[0x08,0x00,0x00,0x00],[0x04,0x00,0x00,0x00],
	[0x02,0x00,0x00,0x00],[0x01,0x00,0x00,0x00]]
	guessKeyVector=[]
	for i in range(4):
		for j in range(4):
			guessKeyVector.append(key[j][i])
	for rcon in rcons:
		guessKeyVector=PreviousRoundKey(guessKeyVector,rcon)
	return guessKeyVector

def PreviousRoundKey(key,rcon):
	rk=[]
	for i in range(16):
		if i==0:
			rk.append(key[0]^(SubByte(key[13]^key[9])^rcon[0]))
		elif i==1:
			rk.append(key[1]^(SubByte(key[14]^key[10])^rcon[1]))
		elif i==2:
			rk.append(key[2]^(SubByte(key[15]^key[11])^rcon[2]))
		elif i==3:
			rk.append(key[3]^(SubByte(key[12]^key[8])^0x00))
		else:
			rk.append(key[i]^key[i-4])
	return rk

SubByte = lambda b: sbox[b]
SubBytes  = np.vectorize(lambda b: sbox[b])
Str2Bytes = lambda string: list(map(lambda n: int(n, 16), string))
RightFormula = lambda b,e: SubByte(b)^e
LeftFormula = lambda b,e,n: SubByte(b^(pmul(n,e)))
ShiftRowsdDual = lambda m, sgn: np.array([np.roll(row, sgn*i) for i, row in enumerate(m)], dtype=np.uint8)
ShiftRows = lambda m: ShiftRowsdDual(m, -1)

if __name__ == "__main__":
	limit=0
	log=False
	if len(sys.argv)<2:
		print("[DFA] Provide a valid .dat file.")
		sys.exit(0)
	else:
		for param in sys.argv:
			if "limit=" in param:
				limit=int(param)
			elif "-log" in param:
				log=True
				logs=open("dfa-log.txt","w")

	print(f"[DFA] Trace file selected: {sys.argv[1]}.")
	print(f"[DFA] Candidates needed: {limit}.")
	print("[DFA] Logging "+("enabled." if log else "disabled."))
	file=open(sys.argv[1],"r")
	readfile=file.read().split()
	
	original=np.array(Str2Bytes(readfile[0].split(','))).reshape(4,4).T
	traces=map(lambda string: np.array(Str2Bytes(string.split(','))).reshape(4,4).T, readfile[1:])
	xorfaults=list(map(lambda fault: fault^original, traces))
	patterns=[np.array([[1,0,0,0],[0,0,0,1],[0,0,1,0],[0,1,0,0]]),np.array([[0,1,0,0],[1,0,0,0],[0,0,0,1],[0,0,1,0]]),np.array([[0,0,1,0],[0,1,0,0],[1,0,0,0],[0,0,0,1]]),np.array([[0,0,0,1],[0,0,1,0],[0,1,0,0],[1,0,0,0]])]
	
	matrix=GenerateEOUTMatrix(patterns,xorfaults)
	allCandidates=FindAllCandidates(matrix,limit)
	subKey10=GetSubKey10(allCandidates,original)
	masterKey=Round2MasterKey(subKey10)
	print("[DFA] SubKey10.")
	print(vhex(subKey10))
	print("[DFA] MasterKey.")
	print(vhex(masterKey))
	
	if logs:
		logs.write(str(allCandidates))