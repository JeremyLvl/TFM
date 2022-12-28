from PVSS import *

#Voter ------------------------------------
class Voter(Dealer):

	def __init__(self, idx, params):
		self.idx = idx
		super().__init__(params, 'voter', 'tallier')

	def vote(self, jdx_pk):
		#random vote
		v=randint(0,1)
		print('voter', self.idx, 'votes', v)
		#self.secret created in Dealer.init
		#split secret into shares for talliers
		broadcast = self.gen_shares(1, jdx_pk)

		#add voter idx to broadcast
		broadcast['idx'] = self.idx

		#secret and vote
		C = pow(self.g, self.secret, self.p)
		U = pow(self.h, (self.secret+v)%self.q, self.p)

		broadcast['secret commits'] = {'secret': C,
									  'vote': U}

		#proof of valid vote
		w = randint(3, self.q)
		r = [0,0]
		d = [0,0]
		a = [0,0]
		b = [0,0]
		r[1-v] = randint(3, self.q)
		d[1-v] = randint(3, self.q)

		a[v] = pow(self.g, w, self.p)
		b[v] = pow(self.h, w, self.p)
		a[1-v] = (pow(self.g, r[1-v], self.p) * pow(C, d[1-v], self.p)) % self.p
		frac_1 = pow(self.h, v-1, self.p)
		frac_2 = (U * frac_1) % self.p
		b[1-v] = (pow(self.h, r[1-v], self.p) * pow(frac_2, d[1-v], self.p)) % self.p

		chal = self.hash([a,b])%self.q

		d[v] = (chal - d[1-v]) % self.q
		r[v] = (w - self.secret * d[v]) % self.q
		
		broadcast['voter proof'] = {'commit': [a,b],
								   'chal': chal,
								   'resp': [d,r]}
	
		return broadcast
		

#Tallier ----------------------------------
class Tallier(Party):

	def __init__(self, jdx, n, params):
		#store number of votes
		self.n = n
		super().__init__(jdx, params, 'tallier')

	def sum_shares(self, shares):
		#sum received shares
		prod = 1
		for share in shares:
			prod = (prod * share) % self.p
		
		#decrypt share sum
		sk_inv = pow(self.sk, -1, self.q)
		share_sum = pow(prod, sk_inv, self.p)
		
		return share_sum

	def count_votes(self, jdx_votes, idx_U):
		#gather share sums to recover sum of secrets
		secret_sum = self.secret_prod(jdx_votes)
		
		#compute product of U's to find sum of secrets and votes
		U_prod = 1
		for U in list(idx_U.values()):
			U_prod = (U_prod * U) % self.p
			
		#compute sum of votes
		secret_sum_inv = pow(secret_sum, -1, self.p)
		vote_sum = (U_prod * secret_sum_inv) % self.p

		#discrete log to find sum of votes
		total_votes = -1
		for a in range(0,self.n+1):
			if pow(self.h,a,self.p)==vote_sum:
				total_votes = a
				break

		print('tallier', self.idx, 'counted', total_votes, 'votes in favour, out of',self.n,'total')


#Voting Verifier ---------------------------
class Voting_Verifier:

	def __init__(self, params):
		#group parameters
		self.p = params['mod p']
		self.q = params['order q']
		self.h = params['generator h']
		self.g = params['generator g']

	def verify_vote(self, broadcast):
		a,b = broadcast['voter proof']['commit']
		chal = broadcast['voter proof']['chal']
		d,r = broadcast['voter proof']['resp']
		C = broadcast['secret commits']['secret']
		U = broadcast['secret commits']['vote']
		
		CHAL = (d[0]+d[1]) % self.q
		A = [(pow(self.g, r[0], self.p) * pow(C, d[0], self.p))%self.p,
			(pow(self.g,r[1],self.p) * pow(C, d[1], self.p))%self.p]
		frac_1 = pow(self.h,-1, self.p)
		frac_2 = (U * frac_1)%self.p
		B = [(pow(self.h, r[0], self.p) * pow(U, d[0],self.p))%self.p,
			(pow(self.h, r[1], self.p) * pow(frac_2, d[1], self.p))%self.p]

		#voter idx
		v_idx = broadcast['idx']
		if chal == CHAL and A==a and B==b:
			print("voting verifier has validated voter", v_idx, "'s vote")
		else:
			print("voting verifier could not validate voter", v_idx, "'s vote")