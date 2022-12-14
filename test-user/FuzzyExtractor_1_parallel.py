import json
import hmac
import cProfile
import multiprocessing
import numpy as np
import random
import string
import time
from hashlib import sha3_256, sha512, sha3_512
import ast
import lsh
import clr
import os
import math
import warnings
warnings.filterwarnings("ignore", category=np.VisibleDeprecationWarning) 
clr.AddReference('MccSdk')
Sigma = 1
Nperm = 600
Nkernel = 2
Kwindow = 128
import BioLab.Biometrics.Mcc.Sdk
class FuzzyExtractor:

    def __init__(self, hash=sha3_256, selection_method="Uniform"):
        self.hash = hash
        self.selection_method=selection_method

    #TODO Haven't converted this to Python3.  Current implementation doesn't require
    # confidence information so we'll leave it alone for now
    def gen_config(self, real, bits, config):
        with open(config, "r") as f:
            c = json.load(f)
        c['confidence']['reals'] = real
        return self.gen(bits, c['locker_size'], c['lockers'], c['confidence'])

    def sample_uniform(self, size, biometric_len, number_samples=1, confidence=None):
        if confidence is None:
            pick_range = range(0, biometric_len-1)
        else:
            pick_range = self.confidence_range(
            confidence, list(range(0, biometric_len-1)))

            print(len(pick_range))
            if(len(pick_range) < 1024):
               return "Confidence range too small"

        randGen = random.SystemRandom()
        return np.array([randGen.sample(pick_range, size) for x in range(number_samples)])

    #TODO write this
    def sample_sixia(self, size, biometric_len, number_samples=1, confidence=None):
        if confidence is None:
            print("Can't run Smart sampling without confidence, calling uniform")
            return self.sample_uniform(size, biometric_len, number_samples, confidence)
        #TODO write

    def gen(self, bits, locker_size=43, lockers=10000, confidence=None):
        length = self.hash().digest_size
        key_len = int(length/2)
        pad_len = int(length - length/2)
        r = self.generate_sample(size=key_len)
        zeros = bytearray([0 for x in range(pad_len)])
        check = zeros + r
        seeds = self.generate_sample(length=lockers, size=16)
        p = []
        positions = None
        if self.selection_method == "Uniform":
            positions = self.sample_uniform(locker_size, biometric_len=len(bits), number_samples=lockers, confidence=confidence)
        if self.selection_method == "Smart":
            positions = self.sample_sixia(locker_size, biometric_len=len(bits), number_samples=lockers, confidence=confidence)
        for x in range(lockers):
            v_i = np.array([bits[y] for y in positions[x]])
            seed = seeds[x]
            h = bytearray(hmac.new(seed, v_i, self.hash).digest())
            c_i = self.xor(check, h)
            p.append((c_i, positions[x], seed))
        return r, p

    def confidence_range(self, confidence, bits):
        indeces = []
        for x in range(len(confidence['reals'])):
            r = confidence['reals'][x]
            if(not (r > confidence['positive_start'] and r < confidence['positive_end']) or (r < confidence['negative_start'] and r > confidence['negative_end'])):
                indeces.append(x)
        return np.delete(bits, indeces)

    def rep(self, bits, p, num_processes=1):
        finished = multiprocessing.Array('b', False)
        split = np.array_split(p, num_processes)
        finished = multiprocessing.Manager().list(
            [None for x in range(num_processes)])
        processes = []
        for x in range(num_processes):
            p = multiprocessing.Process(
                target=self.rep_process, args=(bits, split[x], finished, x))
            processes.append(p)
            p.start()
        for p in processes:
            p.join()
        if any(finished):
            print("Rep succeeded")
            return next(item for item in finished if item is not None)
        print("Rep failed")
        return None

    def rep_process(self, bits, p, finished, process_id):
        counter = 0
   #     print("Rep processing with "+str(process_id))
        for c_i, positions, seed in p:
            v_i = np.array([bits[x] for x in positions])
            h = bytearray(hmac.new(seed, v_i, self.hash).digest())
            res = self.xor(c_i, h)
            keyLen = int(len(res)/2)
            if self.check_result(res):
                finished[process_id] = res[keyLen:]
                return
            counter += 1
            if counter == 1000:
  #              print(str(process_id)+" resetting counter")
                if(not any(finished)):
                    counter = 0
                else:
                    return

    def check_result(self, res):
        padLen = int(len(res)-len(res)/2)
        return all(v == 0 for v in res[:padLen])

    def xor(self, b1, b2):
        return bytearray([x ^ y for x, y in zip(b1, b2)])

    def generate_sample(self, length=0, size=32):
        if(length == 0):
            return bytearray([random.SystemRandom().randint(0, 255) for x in range(int(size))])
        else:
            samples = []
            for x in range(length):
                samples.append(
                    bytearray([random.SystemRandom().randint(0, 255) for x in range(int(size))]))
            return samples
def arraytosbin(arr):
    res=[]
    for i in range(0,len(arr)):
        k="{0:b}".format(int(arr[i]))
        a=len(k)
        while (len(k) < 10):
            k="0"+str(k)
        a=len(k)
        re=[]
        for i in k:
            re.append(int(i))
        res.append(re)
    n1=np.array(res).flatten()
    return n1
def read(path):
    with open(path, 'r') as f:
        return json.load(f)
def savefile(p):
    file = open("file1.txt", "w")
    for i in range(0,len(p)):
        arr=p[i][0]
        arr=bytes(arr)
        b = list(arr)
        content = str(b)+"\n"
        file.write(content)
        arr1=list(p[i][1])
        content = str(arr1)+"\n"
        file.write(content)
        arr2=p[i][2]
        arr2=bytes(arr2)
        c = list(arr2)
        content = str(c)+"\n"
        file.write(content)
    file.close()
    return None
def loadfile(path):
    p = []
    f = open(path, "r")
    line=f.readlines()
    for i in range (0,len(line),3):
        arr=json.loads(line[i])
        arr=bytes(arr)
        arr=bytearray(arr)
        arr1=json.loads(line[i+1])
        arr1=np.array(arr1)
        arr2=json.loads(line[i+2])
        arr2=bytes(arr2)
        arr2=bytearray(arr2)
        p.append((arr,arr1,arr2))
    return p
def tranfor(a,G_vecs):
    binary_codes=np.zeros(Nperm,dtype=np.int16)
    binary_codes,G_vecs=lsh.WTA_hashing(a,G_vecs,Nkernel, Kwindow, Nperm)
    return binary_codes
def istto(test):
    test=BioLab.Biometrics.Mcc.Sdk.MccSdk.CreateMccTemplateFromIsoTemplate(test)   
    ft=np.zeros((1,420))
    ft=np.array(ft).flatten()
    for i in range(1,421):
        os.chdir(r"C:\Users\MSI\OneDrive - Tr?????ng ??H CNTT - University of Information Technology\M??y t??nh\New folder (2)\kpca_vec\training")
        test1=BioLab.Biometrics.Mcc.Sdk.MccSdk.CreateMccTemplateFromIsoTemplate(str(i)+".ist")
        tmp=BioLab.Biometrics.Mcc.Sdk.MccSdk.MatchMccTemplates(test, test1)
        ft[i-1]=math.exp((-0.5*(1-tmp)*(1-tmp))/(Sigma*Sigma))
    return ft
from scipy.spatial.distance import hamming
import scipy.io as sio
if __name__ == '__main__':
    """
    data = sio.loadmat("tests/test_files/6_1.mat")
    a1 = data['a']
    a1=np.array(a1).flatten()
    a1=arraytosbin(a1)
    #fe = FuzzyExtractor()
    #r, p = fe.gen(a1, locker_size=32, lockers=20000, confidence=None)
    #savefile(p)
    data = sio.loadmat("tests/test_files/6_1.mat")
    a1 = data['a']
    a1=np.array(a1).flatten()
    a1=arraytosbin(a1)
    data = sio.loadmat("tests/test_files/6_2.mat")
    b1 = data['a']
    b1=np.array(b1).flatten()
    b1=arraytosbin(b1)
    data=sio.loadmat("tests/test_files/140_1.mat")
    c1 = data['a']
    c1=np.array(c1).flatten()
    c1=arraytosbin(c1)
    f1 = read("tests/test_files/test.bin")
    f2 = read("tests/test_files/same.bin")
    f3 = read("tests/test_files/diff.bin")
    #print(hamming(a1, c1)*len(a1) )
    fe = FuzzyExtractor()
    #r, p = fe.gen(a1, locker_size=32, lockers=20000, confidence=None)
    #print(r)
    #savefile(p)
    p1=loadfile("file1.txt")
    print("Testing rep with same value")
    a=fe.rep(a1, p1, num_processes=4)
    print(a)
    print("Testing rep with value from same biometric")
    a=fe.rep(b1, p1, num_processes=4)
    print(a)
    print("Testing rep with value from different biometric")
    a=fe.rep(c1, p1, num_processes=4)
    print(a)
    #cProfile.run("fe.gen(f1, lockers=1000)", sort='cumtime')
    #cProfile.run("fe.rep(f2, p)", sort="cumtime")
    """
    data = sio.loadmat("kpca_vectest.mat")
    a = data['W']
    Sigma = 1
    Nperm = 600
    Nkernel = 2
    Kwindow = 128
    G_vecs=[]
    os.chdir(r"C:\Users\MSI\OneDrive - Tr?????ng ??H CNTT - University of Information Technology\M??y t??nh\test-otp")
    G_vecs=np.load("test123.npy")
    test=r"D:\kltn\chuyenquapgm\flieist\7_2.ist"
    ft=istto(test)
    c=ft.dot(a)
    binary1=tranfor(c,G_vecs)
    test=r"D:\kltn\chuyenquapgm\flieist\7_3.ist"
    ft=istto(test)
    c=ft.dot(a)
    binary2=tranfor(c,G_vecs)
    count=lsh.match(binary1,binary2)
    print(count/600)
    a1=arraytosbin(binary1)
    b1=arraytosbin(binary2)
    print(hamming(a1, b1))
    fe = FuzzyExtractor()
    for i in range (1,11):
        r, p = fe.gen(a1, locker_size=32, lockers=75000, confidence=None)
        b1=arraytosbin(binary2)
        a=fe.rep(b1, p, num_processes=4)
        print(a)
#1096