from Voting import Voter, Tallier, Voting_Verifier
from Voting import Verifier as PVSS_Verifier

#group parameters
p = 1907
q = 953
h = 3
g = 4
params = {'mod p': p,
		  'order q': q,
		  'generator h': h,
		  'generator g': g}

#construct voters
num_voters = int(input('Number of voters:',))
Voters = [Voter(i+1, params) for i in range(0, num_voters)]

#construct talliers
num_talliers = int(input('number of talliers:'))
jdx_T = {j+1 : Tallier(j+1, num_voters, params) for j in range(0,num_talliers)}
jdx_pk = {j : jdx_T[j].pk for j in jdx_T}

#construct PVSS and voting verifiers
PVSS_V = PVSS_Verifier(params, 'voter', 'party')
Voting_V = Voting_Verifier(params)

#store voter broadcast
idx_broadcast = {}
#store shares for tallier j
jdx_shares = {}
for jdx in jdx_pk:
	jdx_shares[jdx]=[]

#store vote/secret encryption for voter i
idx_U = {}

#voters vote
for V in Voters:
	#each voter sends their voting information
	broadcast = V.vote(jdx_pk)
	idx_broadcast[V.idx] = broadcast
	
	#store the vote/secret encryption
	idx_U[V.idx] = broadcast['secret commits']['vote']

#verifiers check votes and distributions
for V in Voters:
	broadcast = idx_broadcast[V.idx]
	
	#verify vote
	Voting_V.verify_vote(broadcast)
	#verify distribution of vote
	PVSS_V.dealer_proof(jdx_pk, broadcast)

	#prepare encrypted shares for each tallier
	for jdx in jdx_pk:
		jdx_shares[jdx].append(broadcast['idx enc'][jdx])

#talliers sum shares
jdx_share_sum = {}
for T in jdx_T:
	jdx_share_sum[T] = jdx_T[T].sum_shares(jdx_shares[T])

#talliers count votes
for T in jdx_T:
	jdx_T[T].count_votes(jdx_share_sum, idx_U)