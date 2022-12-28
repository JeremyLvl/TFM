import numpy as np
import math as m
from random import randint
from fractions import Fraction
from hashlib import sha256

#toggle printing of details during run-through
details = True

#PARTY --------------------------------------
class Party:

	#initiate party
	def __init__(self, idx, params, name='party'):
		self.idx = idx
		self.name = name
		#group parameters
		self.p = params['mod p']
		self.q = params['order q']
		self.h = params['generator h']
		self.g = params['generator g']

		#key pair such that pk is not 1
		self.pk = 1
		while self.pk == 1:
			self.sk = randint(3, self.q)
			self.pk = pow(self.h, self.sk, self.p)

		global details
		if details:
			print(self.name,'initialised with sk:', self.sk, ', pk:',self.pk)
	
		return None

	#receive dealer broadcast and decrypt own share
	def receive_dealer_info(self, broadcast):
		#store threshold and own encrypted share
		self.t = broadcast['t']
		self.enc_share = broadcast['idx enc'][self.idx]

		#decrypt share using inverse of sk in Z/qZ
		sk_inv = pow(self.sk, -1, self.q)
		self.share = pow(self.enc_share, sk_inv, self.p)
		
		#store shares of authorised set A
		self.A_shares = {self.idx: self.share}

		global details
		if details:
			print(self.name, self.idx, 'decrypted own share to', self.share)

		return None
			
	#broadcast share and proof of correct decryption
	def broadcast_share(self):

		#DLEQ proof for h^sk = pk and s^sk = Y
		w = np.random.randint(self.q)
		A = pow(self.h, w, self.p)
		B = pow(self.share, w, self.p)
		#challenge hash
		to_hash = repr([self.h, self.pk, self.share, self.enc_share, A, B]).encode('utf-8')
		chal = int.from_bytes(sha256(to_hash).digest(), 'big')
		#response
		resp = (w - (self.sk * chal)) % self.q
		dec_proof = {'w': w,
					 'chal': chal,
					 'resp': resp}

		print(self.name,self.idx,'broadcast decrypted share as',self.share,'and proof of decryption')
		return self.idx, self.share, dec_proof
		
	#receive shares from party in A
	def receive_party_info(self, from_idx, received_share):
		#add share to authorised set
		self.A_shares[from_idx] = received_share

		global details
		if details:
			print(self.name, self.idx, 'received encrypted share from', from_idx, 'as', received_share)

		#given sufficient shares, start reconstruction
		if len(self.A_shares) >= self.t:
			self.recover_secret()

		return None

	#recover secret
	def recover_secret(self):
		self.secret = self.secret_prod(self.A_shares)
		
		if details:
			print(self.name, self.idx, 'recovered secret', self.secret)

		return None

	def secret_prod(self, idx_shares):
		prod = 1	
		for idx in idx_shares:
			#compute lambda from indices
			indices = list(idx_shares.keys())
			indices.remove(idx)
			lambdas = [Fraction(j,j-idx) for j in indices]
			L = m.prod(lambdas)

			#get share as base of power
			share = idx_shares[idx]
			base = share
			
			#find root if lambda is fraction
			if L.denominator != 1:
				denom_inv = pow(L.denominator, -1, self.q)
				base = pow(share, denom_inv, self.p)
			
			#multiply product
			prod = (prod* pow(base, L.numerator, self.p))%self.p
			
		#compute final secret
		return int(prod%self.p)
		

#DEALER --------------------------------------
class Dealer:

	#initialise dealer
	def __init__(self, params, name='dealer', party_name='party'):
		self.name = name
		self.party_name = party_name
		
		#group parameters
		self.p = params['mod p']
		self.q = params['order q']
		self.h = params['generator h']
		self.g = params['generator g']
		
		#store secret
		self.secret = randint(2, self.q)

		global details
		if details:
			print(self.name, 'initialised with shared secret', pow(self.h,self.secret,self.p))

		return None

	#generates shares
	def gen_shares(self, t_prop, idx_pk):
		#prepare broadcast
		broadcast = {}
		
		#compute number of parties and threshold
		n = len(idx_pk)
		t = round(n * t_prop)
		broadcast['t'] = t
		
		#generate random polynomial with p(0)=secret
		coefs = np.random.randint(self.q, size=t-1)
		coefs = np.append(coefs, self.secret)
		poly = np.poly1d(coefs)

		#compute each user's share
		idx_enc = {}
		for idx in idx_pk:
			#compute share as pk^{p(i)}
			pk = idx_pk[idx]
			idx_enc[idx] = pow(pk,int(poly(idx)),self.p)
			
			if details:
				print('share for', self.party_name, idx, 'encrypted as', idx_enc[idx])
		
		broadcast['idx enc'] = idx_enc

		#compute commitments to coefs of poly as g^{coef}
		coef_commits = [pow(self.g, int(coef), self.p) for coef in coefs]
		broadcast['coef commits'] = coef_commits

		#get indices list with 0
		indices_0 = list(idx_pk)
		indices_0.insert(0,0)
		
		#gather commits for proof as X
		idx_X = {}
		for idx in idx_pk:
			Xi_elems = [pow(coef_commits[t-1-j], pow(idx,j), self.p) for j in range(0,t)]
			Xi_prod = 1
			for Xi_elem in Xi_elems:
				Xi_prod = (Xi_prod * Xi_elem)%self.p
			idx_X[idx] = Xi_prod
		
		#elements for proof of knowledge of p(i)
		W = np.random.randint(self.q, size=n+1)
		idx_A, idx_B = {}, {}
		for idx in idx_pk:
			idx_A[idx] = pow(self.g, int(W[idx]), self.p)
			idx_B[idx] = pow(idx_pk[idx], int(W[idx]), self.p)

		#gather elements and hash for challenge
		chal = self.hash([idx_X, idx_enc, idx_A, idx_B])

		#responses to challenge
		idx_resp = {}
		for idx in idx_pk:
			idx_resp[idx] = (W[idx] - int(poly(idx)) * chal) % self.q
		
		#broadcast proof as challenge and response
		broadcast['dealer proof'] = {'chal': chal,
									 'idx_resp': idx_resp}

		if details:
			print(self.name, 'broadcasts proof of distribution')
		
		#return threshold and encrypted shares for broadcast
		return broadcast

	#hash list to integer 
	def hash(self, to_hash_list):
		to_hash = repr(to_hash_list).encode('utf-8')
		return int.from_bytes(sha256(to_hash).digest(), 'big')
		


#VERIFIER --------------------------------------
class Verifier:

	#initialise dealer
	def __init__(self, params, dealer_name='dealer', party_name='party'):
		self.dealer_name = dealer_name
		self.party_name = party_name
		
		#group parameters
		self.p = params['mod p']
		self.q = params['order q']
		self.h = params['generator h']
		self.g = params['generator g']

		return None

	#verify dealer proof
	def dealer_proof(self, idx_pk, broadcast):
		t= broadcast['t']
		idx_enc = broadcast['idx enc']
		coef_commits = broadcast['coef commits']
		c = broadcast['dealer proof']['chal']
		idx_resp = broadcast['dealer proof']['idx_resp']
		#get indices list with 0
		indices_0 = list(idx_pk)
		indices_0.insert(0,0)
		
		#compute X, A, B
		idx_X, idx_A, idx_B = {}, {}, {}
		t = len(coef_commits)
		for idx in idx_pk:
			Xi_elems = [pow(coef_commits[t-1-j], pow(idx,j), self.p) for j in range(0,t)]
			Xi_prod = 1
			for Xi_elem in Xi_elems:
				Xi_prod = (Xi_prod * Xi_elem)%self.p
			idx_X[idx] = Xi_prod
			idx_A[idx] = (pow(self.g, idx_resp[idx], self.p)
						  * pow(idx_X[idx], c, self.p)) % self.p
			idx_B[idx] = (pow(idx_pk[idx], idx_resp[idx], self.p)
						  * pow(idx_enc[idx], c, self.p)) % self.p
			
		#hash as dealer did and check chal is the same
		to_hash = repr([idx_X, idx_enc, idx_A, idx_B]).encode('utf-8')
		chal = int.from_bytes(sha256(to_hash).digest(), 'big')

		global details
		if details:
			if chal == c:
				print("verifier has validated",self.dealer_name,"'s distribution")
			else:
				print("verifier could not validate",self.dealer_name,"'s distribution")
		return None

	#verify party decryption proof, standard DLEQ(h, pk, s, Y)
	def party_proof(self, share, proof, idx_enc, idx_pk, idx):
		w = proof['w']
		chal = proof['chal']
		resp = proof['resp']
		
		a = pow(self.h, w, self.p)
		b = pow(share, w, self.p)
		A = (pow(self.h, resp, self.p)
			 * pow(idx_pk[idx], chal, self.p)) % self.p
		B = (pow(share, resp, self.p) 
			* pow(idx_enc[idx], chal, self.p)) % self.p

		global details
		if details:
			if a==A and b==B:
				print("verifier has validated",self.party_name,idx,"'s share")
			else:
				print("verifier could not validate party",self.party_name,"'s share")
		return None