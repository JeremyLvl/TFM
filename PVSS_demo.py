import PVSS

#group parameters
p = 1907
q = 953
h = 348
g = 483
params = {'mod p': p,
		  'order q': q,
		  'generator h': h,
		  'generator g': g}


#get values from user
n = int(input('number of parties: '))
auth_str = input("authorised parties (subset of [1,2,...,"+str(n)+"]): ")
auth_list = auth_str.split(',')
auth = [int(idx) for idx in auth_list]
#construct dealer with random secret
d = PVSS.Dealer(params)

#construct parties
idx_P = {i:PVSS.Party(i, params) for i in range(1,n+1)}
idx_pk = {i:idx_P[i].pk for i in idx_P}

#construct verifier
V = PVSS.Verifier(params)

#broadcast encrypted shares
t = len(auth)/n
broadcast = d.gen_shares(t, idx_pk)
idx_enc = broadcast['idx enc']

#verifier checks proof of distribution
V.dealer_proof(idx_pk, broadcast)

#parties receive encrypted shares
for P in idx_P.values():
	P.receive_dealer_info(broadcast)

#set authorised set
A = [idx_P[i] for i in auth]

#authorised set reconstructs
for P in A:
	#get broadcast info
	idx, share, dec_proof = P.broadcast_share()
	#verifier checks parties shares
	V.party_proof(share, dec_proof, idx_enc, idx_pk, idx)
	#party receive share from authorised set
	for B in A:
		if B != P:
			B.receive_party_info(idx, share)

