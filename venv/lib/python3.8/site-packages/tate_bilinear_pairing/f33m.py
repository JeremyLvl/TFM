"""
This module is about operations over the Galois Field $GF(3^{3*m})$. 
Such field is an extension field that is $GF(3^m)[z]/h(z)$ where $h(z)=z^3-z-1$.
For more information about such extension field, please read 
the paper by T. Kerins, W. P. Marnane, E. M. Popovici, and P.S.L.M. Barreto,
"Efficient hardware for the Tate pairing calculation in characteristic three".
"""

from . import f3m

def zero():
    'the zero element in $GF(3^{3*m})$'
    return [f3m.zero(), f3m.zero(), f3m.zero()]

def one():
    'the element with value of one in $GF(3^{3*m})$'
    return [f3m.one(), f3m.zero(), f3m.zero()]

def random():
    'a random element in $GF(3^{3*m})$'
    return [f3m.random(), f3m.random(), f3m.random()]

def add(a, b, c):
    '''addition in $GF(3^{3*m})$
    
    :param a: the first operand
    :type a: list
    :param b: the second operand
    :type b: list
    :param c: the destination. $c == a+b \in GF(3^{3*m})$
    :type c: list
    :returns: None
    
    '''
    f3m.add(a[0], b[0], c[0])
    f3m.add(a[1], b[1], c[1])
    f3m.add(a[2], b[2], c[2])

def neg(a, c):
    '''negation in GF(3^{3*m})
    
    :param a: the operand
    :type a: list
    :param c: the destination. $c == -a \in GF(3^m)$
    :type c: list
    :returns: None
    
    '''
    f3m.neg(a[0], c[0])
    f3m.neg(a[1], c[1])
    f3m.neg(a[2], c[2])

def sub(a, b, c):
    '''subtraction in $GF(3^{3*m})$
    
    :param a: the first operand
    :type a: list
    :param b: the second operand
    :type b: list
    :param c: the destination. $c == a-b \in GF(3^{3*m})$
    :type c: list
    :returns: None
    
    '''
    f3m.sub(a[0], b[0], c[0])
    f3m.sub(a[1], b[1], c[1])
    f3m.sub(a[2], b[2], c[2])

def mult(a, b):
    '''multiplication in $GF(3^{3*m})$
    
    :param a: the first operand
    :type a: list
    :param b: the second operand
    :type b: list
    :returns: list, $c == a*b \in GF(3^{3*m})$
    
    '''
    a0, a1, a2 = a
    b0, b1, b2 = b
    t0 = f3m.zero()
    t1 = f3m.zero()
    c1 = f3m.zero()
    a0b0 = f3m.mult(a0, b0)
    a1b1 = f3m.mult(a1, b1)
    a2b2 = f3m.mult(a2, b2)
    d0 = a0b0
    f3m.add(a1, a0, t0)
    f3m.add(b1, b0, t1)
    d1 = f3m.mult(t0, t1)
    f3m.sub(d1, a1b1, d1)
    f3m.sub(d1, a0b0, d1)
    f3m.add(a2, a0, t0)
    f3m.add(b2, b0, t1)
    d2 = f3m.mult(t0, t1)
    f3m.add(d2, a1b1, d2)
    f3m.sub(d2, a2b2, d2)
    f3m.sub(d2, a0b0, d2)
    f3m.add(a2, a1, t0)
    f3m.add(b2, b1, t1)
    d3 = f3m.mult(t0, t1)
    f3m.sub(d3, a2b2, d3)
    f3m.sub(d3, a1b1, d3)
    d4 = a2b2
    f3m.add(d0, d3, t0)
    c0 = t0
    f3m.add(d1, d3, c1)
    f3m.add(c1, d4, c1)
    f3m.add(d2, d4, t1)
    c2 = t1
    return [c0, c1, c2]

def inverse(a):
    '''inversion in $GF(3^{3*m})$
    
    :param a: the operand
    :type a: list
    :returns: list, $ == a^{-1} \in GF(3^{3*m})$
    
    '''
    a0, a1, a2 = a
    a02 = f3m.mult(a0, a0)
    a12 = f3m.mult(a1, a1)
    a22 = f3m.mult(a2, a2)
    v0 = f3m.zero()
    f3m.sub(a0, a2, v0) # v0 == a0-a2
    delta = f3m.mult(v0, a02) # delta = (a0-a2)*(a0^2)
    f3m.sub(a1, a0, v0) # v0 == a1-a0
    c0 = f3m.mult(v0, a12) # c0 == (a1-a0)*(a1^2)
    f3m.add(delta, c0, delta) # delta = (a0-a2)*(a0^2) + (a1-a0)*(a1^2)
    f3m.sub(a2, v0, v0) # v0 == a2-(a1-a0) = a0-a1+a2
    c1 = f3m.mult(v0, a22) # c1 == (a0-a1+a2)*(a2^2)
    f3m.add(delta, c1, delta) # delta = (a0-a2)*(a0^2) + (a1-a0)*(a1^2) + (a0-a1+a2)*(a2^2)
    delta = f3m.inverse(delta) # delta = [(a0-a2)*(a0^2) + (a1-a0)*(a1^2) + (a0-a1+a2)*(a2^2)] ^ {-1}
    f3m.add(a02, a22, v0) # v0 == a0^2+a2^2
    c2 = f3m.mult(a0, a2) # c2 == a0*a2
    f3m.sub(v0, c2, c0) # c0 == a0^2+a2^2-a0*a2
    f3m.add(a1, a2, v0) # v0 == a1+a2
    c3 = f3m.mult(a1, v0) # c3 == a1*(a1+a2)
    f3m.sub(c0, c3, c0) # c0 == a0^2+a2^2-a0*a2-a1*(a1+a2)
    c0 = f3m.mult(c0, delta) # c0 *= delta
    c1 = f3m.mult(a0, a1) # c1 == a0*a1
    f3m.sub(a22, c1, c1) # c1 == a2^2-a0*a1
    c1 = f3m.mult(c1, delta) # c1 *= delta
    f3m.sub(a12, c2, c2) # c2 == a1^2-a0*a2
    f3m.sub(c2, a22, c2) # c2 == a1^2-a0*a2-a2^2
    c2 = f3m.mult(c2, delta) # c2 *= delta
    return [c0, c1, c2]

