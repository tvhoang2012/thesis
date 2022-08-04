from turtle import position
import numpy as np
def swapposition(a=None , b=None):
    tam=[]
    for i in b:
        tam.append(a[int(i)])
    return tam  
def match(a= None, b=None):
    c=np.subtract(a,b)
    count=0
    for i in c:
        if(i==0):
            count=count+1
    return count  
def getGvec(K,G):
  G_vecs=np.zeros((G,K))
  for i in range(G):
    rg=np.random.default_rng()
    G_vecs[i,:] = rg.permutation(K)
  return G_vecs
def randompern(Nperm,G_vecs,Nkernel):
  for i in range(Nperm):
    G_vecs.append(np.zeros((2,418)))
  for i in range(Nperm):
    G_vecs[i] = getGvec(419,Nkernel)
  return G_vecs
def WTA_hashing(X = None,G_vecs = None,G = None,K = None,Gvm = None): 
    binary_codes = np.zeros(Gvm,dtype=np.int16)
    #binary_codes2 = np.zeros((X.shape[1-1],1))
    for ii in range(Gvm):
        G_vecss=G_vecs[ii]
        segment = np.ones((1,K))
        for i in range(G):
            tam=G_vecss[i,np.arange(0,K)]
            interest_segment = swapposition(X,tam)
            segment = np.multiply(segment,interest_segment)
        #for j in np.arange(1,X.shape[1-1]+1).reshape(-1):
           # D = segment(j,1)
            #for k in np.arange(2,K+1).reshape(-1):
               # if segment(j,k) > D:
               #     D = segment(j,k)
                 #   binary_codes2[j] = k
                #else:
                   # binary_codes2[j] = binary_codes2(j)
        max_position=np.where(segment == np.amax(segment))
        if(len(max_position[1])<=1):
            binary_codes[ii] = max_position[1]
        else:
            binary_codes[ii] = max_position[1][0]
        #binary_codes2 = np.zeros((X.shape[1-1],1))
    
    return binary_codes,G_vecs