"""
This module is about operations over the Galois Field $GF(3^{2*m})$, which is an extension
field of $GF(3^m)[y]/g(y)$, where $g(y)=y^2+1$ is an irreducible polynomial over $GF(3^m)$. 
For more information about such extension field, please read 
the paper by T. Kerins, W. P. Marnane, E. M. Popovici, and P.S.L.M. Barreto,
"Efficient hardware for the Tate pairing calculation in characteristic three".
"""

from . import f3m

def zero():
    'the zero element in $GF(3^{2*m})$'
    return [f3m.zero(), f3m.zero()]

def one():
    'the element with value of one in $GF(3^{2*m})$'
    return [f3m.one(), f3m.zero()]     

def random():
    'a random element in $GF(3^{2*m})$'
    return [f3m.random(), f3m.random()]

def add(a, b, c):
    '''doing addition in $GF(3^{2*m})$
    The function sets $c == a+b$ and returns nothing.'''
    f3m.add(a[0], b[0], c[0])
    f3m.add(a[1], b[1], c[1])

def sub(a, b, c):
    '''doing subtraction in $GF(3^{2*m})$
    The function sets $c == a+b$ and returns nothing.'''
    f3m.sub(a[0], b[0], c[0])
    f3m.sub(a[1], b[1], c[1])

def mult(a, b):
    '''doing multiplication in $GF(3^{2*m})$, and returning $a*b$'''
    a0, a1 = a
    b0, b1 = b
    a0b0 = f3m.mult(a0, b0)
    a1b1 = f3m.mult(a1, b1)
    t0 = f3m.zero()
    t1 = f3m.zero()
    f3m.add(a1, a0, t0)
    f3m.add(b1, b0, t1)
    c1 = f3m.mult(t0, t1) # c1 == (a1+a0)*(b1+b0)
    f3m.sub(c1, a1b1, c1)
    f3m.sub(c1, a0b0, c1)
    c0 = a0b0
    f3m.sub(c0, a1b1, c0) # c0 == a0*b0 - a1*b1
    return [c0, c1]

def cubic(a):
    '''computing the cubic of $a$ in GF(3^{2*m}), and returning $a^3$
    '''
    a0, a1 = a
    c0 = f3m.cubic(a0)
    c1 = f3m.cubic(a1)
    f3m.neg(c1, c1) # c1 == -(a1^3)
    return [c0, c1]
