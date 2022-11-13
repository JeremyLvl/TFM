import numpy as np
from random import randint
from hashlib import sha256


#HASHING ------------------------------------
def hash(param_set):
	hash_list = [str(a) for a in param_set]
	hash_str = ''.join(hash_list)
	hash_utf = hash_str.encode('utf-8')
	h = sha256(hash_utf)
	h_int = int.from_bytes(h.digest(), 'big')
	return h_int


#PARTY --------------------------------------
class Party:
	
	#initiate party with keys
	def __init__(self, params):
		self.params = params
		self.q = params[0]
		self.g_0 = params[1]
		self.g_1 = params[2]
		self.G_0 = params[3]
		self.G_1 = params[4]
		self.sk = randint(2, self.q - 1)
		self.pk_1 = self.power(self.G_0, self.sk)
		self.pk_2 = self.power(self.G_1, self.sk)
		self.A_shares = {}
		print('party initialised with public keys', self.pk_1, self.pk_2)

	#group operations
	def power(self, a, b):
		return pow(int(a), int(b), self.q)

	def inverse(self, a):
		return self.power(a, -1)

	#save index/public key mappings
	def receive_indices(self, idx_pk):
		self.idx_pk = idx_pk
		self.pk_idx = {repr(idx_pk[k]): k for k in idx_pk}
		pk_rep = repr([self.pk_1, self.pk_2])
		self.idx = self.pk_idx[pk_rep]
		print('party with public keys', pk_rep, 'indexed as', self.idx)

	#receive dealer broadcast and decrypt own share
	def receive_dealer_info(self, broadcast):
		self.t = broadcast[0]
		self.idx_enc = broadcast[3]
		enc_share = self.idx_enc[self.idx]
		self.share = self.power(enc_share, self.inverse(self.sk))
		self.A_shares[self.idx] = self.share
		print('party', self.idx, 'decrypted own share to', self.share)

	#reencrypt secret to share with authorised set
	def reencrypt_share(self, A_idx):
		#encrypt share
		idx_Enc = {}
		for idx in A_idx:
			if idx != self.idx:
				pk = self.idx_pk[idx]
				w = np.random.randint(self.q, size=2)
				v = [-self.sk * a for a in w]
				a = (self.power(self.G_0, w[0]) * self.power(self.G_1, w[1])) % self.q
				b = (self.share * self.power(pk[0], w[0]) *
				     self.power(pk[1], w[1])) % self.q

				#proof of knowledge
				K = np.random.randint(self.q, size=5)
				y = self.power(self.G_0 * self.G_1, K[0]) % self.q
				C_Y = (self.power(b, K[0]) * self.power(pk[0], K[1]) *
				       self.power(pk[1], K[2])) % self.q
				C_a = (self.power(self.G_0, K[3]) * self.power(self.G_1, K[4])) % self.q
				C_e = (self.power(a, K[0]) * self.power(self.G_0, K[1]) *
				       self.power(self.G_1, K[2])) % self.q
				c = hash(self.params + pk + [y, C_Y, C_a, C_e])
				#response
				R = [k + c * a for (k, a) in zip(list(K), [self.sk] + v + list(w))]

				#prepare for broadcast
				idx_Enc[idx] = [self.idx, a, b, c, R]

		#broadcast encryted share and proofs for all A parties
		print('party', self.idx, 'encrypted shares for parties', A_idx)
		return idx_Enc

	#receive and decrypt reencrypted shares from party in A
	def receive_party_info(self, idx_Enc):
		received = idx_Enc[self.idx]
		from_idx, a, b = received[0], received[1], received[2]
		received_share = (b * self.inverse(self.power(a, self.sk))) % self.q
		self.A_shares[from_idx] = received_share
		print('party', self.idx, 'decrypted share from', from_idx)
		if len(self.A_shares) >= self.t:
			self.recover_secret()

	#recover secret using reencrypted shares
	def recover_secret(self):
		prod = 1
		for idx in self.A_shares:
			indices_idx = list(self.A_shares.keys())
			indices_idx.remove(idx)
			indices_arr = np.array(indices_idx)
			L = int(np.prod(indices_arr))
			share = self.A_shares[idx]
			prod = (prod * self.power(share, L)) % self.q
		self.secret = prod
		print('party', self.idx, 'recovered secret', self.secret, 'with shares',
		      self.A_shares)


#DEALER --------------------------------------
class Dealer:

	def __init__(self):
		#group parameters
		self.q = 571
		self.g_0 = 3
		self.g_1 = 4
		self.G_0 = 5
		self.G_1 = 6
		self.params = [self.q, self.g_0, self.g_1, self.G_0, self.G_1]
		print('dealer initialised with params', self.params)

	#group operations
	def power(self, a, b):
		return pow(int(a), int(b), self.q)

	#generate random polynomial
	def gen_poly(self, t):
		coefs = np.random.randint(self.q, size=t)
		poly = np.poly1d(coefs)
		print('polynomial generated as', poly)
		return poly

	#generate mapping public_keys -> indices for parties
	def gen_indices(self, public_keys):
		self.idx_pk = {i + 1: public_keys[i] for i in range(0, len(public_keys))}
		print('dealer indexed parties as', self.idx_pk)

	#dealer generates shares
	def gen_shares(self, t_prop):
		#compute number of parties and threshold
		n = len(self.idx_pk)
		t = round(n * t_prop)

		#generate random polynomials
		p_0 = self.gen_poly(t)
		p_1 = self.gen_poly(t)

		#compute shared secret
		self.S = (self.power(self.G_0, p_0(0)) *
		          self.power(self.G_1, p_1(0))) % self.q
		print('shared secret generated as', self.S)

		#compute commitments for coefficients
		C_p = []
		for j in range(0, t):
			a_j0 = p_0.coefficients[t - j - 1]
			a_j1 = p_1.coefficients[t - j - 1]
			C_p.append(
			 (self.power(self.g_0, a_j0) * self.power(self.g_1, a_j1)) % self.q)

		#compute each users share and commitments
		K = np.random.randint(self.q - 1, size=(n + 1, 2))
		idx_Y = dict()
		C_Y = []
		X = []
		C_X = []
		for idx in self.idx_pk:
			pk = self.idx_pk[idx]
			idx_Y[idx] = (self.power(pk[0], p_0(idx)) *
			              self.power(pk[1], p_1(idx))) % self.q
			C_Y.append(
			 (self.power(pk[0], K[idx][0]) * self.power(pk[1], K[idx][1])) % self.q)
			X.append(
			 (self.power(self.g_0, p_0(idx)) * self.power(self.g_1, p_1(idx))) % self.q)
			C_X.append(
			 (self.power(self.g_0, K[idx][0]) * self.power(self.g_1, K[idx][1])) %
			 self.q)
		print('shares generated as', idx_Y)

		#commitment by hashing
		c = hash(self.params + list(idx_Y.values()) + C_Y + X + C_X)

		#generate response for each user
		R = []
		for idx in self.idx_pk:
			r_0 = K[idx][0] + c * p_0(idx)
			r_1 = K[idx][1] + c * p_1(idx)
			R.append([r_0, r_1])

		#return values to broadcast
		return t, c, C_p, idx_Y, R


def test():
	d = Dealer()
	P = []
	for i in range(0, 10):
		P.append(Party(d.params))

	d.gen_indices([[p.pk_1, p.pk_2] for p in P])

	for p in P:
		p.receive_indices(d.idx_pk)

	broadcast = d.gen_shares(0.5)

	for p in P:
		p.receive_dealer_info(broadcast)

	A = [P[i] for i in [2, 3, 5, 7, 8]]
	A_idx = [p.idx for p in A]
	print('authorised parties are', A_idx)

	for p in A:
		p_broadcast = p.reencrypt_share(A_idx)
		for b in A:
			if b != p:
				b.receive_party_info(p_broadcast)
