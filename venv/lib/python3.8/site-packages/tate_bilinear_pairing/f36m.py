"""
This module provides operations over the Galois Field $GF(3^{6*m})$, which is
${GF(3^m)[y]/g(y)}[z]/h(z)$ where $g(y)=y^2+1$, $h(z)=z^3-z-1$.
For more information about such extension field, please read 
the paper by T. Kerins, W. P. Marnane, E. M. Popovici, and P.S.L.M. Barreto,
"Efficient hardware for the Tate pairing calculation in characteristic three".
"""

from . import f32m

def zero():
    'the zero element in $GF(3^{6*m})$'
    return [f32m.zero(), f32m.zero(), f32m.zero()]

def one():
    'the element with value of one in $GF(3^{6*m})$'
    return [f32m.one(), f32m.zero(), f32m.zero()]        

def random():
    'a random element in $GF(3^{6*m})$'
    return [f32m.random(), f32m.random(), f32m.random()]

def add(a, b, c):
    '''addition in $GF(3^{6*m})$
    
    :param a: the first operand
    :type a: list
    :param b: the second operand
    :type b: list
    :param c: the destination. $c == a+b \in GF(3^{6*m})$
    :type c: list
    :returns: None
    
    '''
    f32m.add(a[0], b[0], c[0])
    f32m.add(a[1], b[1], c[1])
    f32m.add(a[2], b[2], c[2])

def sub(a, b, c):
    '''subtraction in $GF(3^{6*m})$
    
    :param a: the first operand
    :type a: list
    :param b: the second operand
    :type b: list
    :param c: the destination. $c == a-b \in GF(3^{6*m})$
    :type c: list
    :returns: None
    
    '''
    f32m.sub(a[0], b[0], c[0])
    f32m.sub(a[1], b[1], c[1])
    f32m.sub(a[2], b[2], c[2])

def mult(a, b):
    '''multiplication in $GF(3^{6*m})$
    
    :param a: the first operand
    :type a: list
    :param b: the second operand
    :type b: list
    :returns: list, $c == a*b \in GF(3^{6*m})$
    
    '''
    a0, a1, a2 = a
    b0, b1, b2 = b
    t0 = f32m.zero()
    t1 = f32m.zero()
    c1 = f32m.zero()
    a0b0 = f32m.mult(a0, b0)
    a1b1 = f32m.mult(a1, b1)
    a2b2 = f32m.mult(a2, b2)
    d0 = a0b0
    f32m.add(a1, a0, t0)
    f32m.add(b1, b0, t1)
    d1 = f32m.mult(t0, t1)
    f32m.sub(d1, a1b1, d1)
    f32m.sub(d1, a0b0, d1)
    f32m.add(a2, a0, t0)
    f32m.add(b2, b0, t1)
    d2 = f32m.mult(t0, t1)
    f32m.add(d2, a1b1, d2)
    f32m.sub(d2, a2b2, d2)
    f32m.sub(d2, a0b0, d2)
    f32m.add(a2, a1, t0)
    f32m.add(b2, b1, t1)
    d3 = f32m.mult(t0, t1)
    f32m.sub(d3, a2b2, d3)
    f32m.sub(d3, a1b1, d3)
    d4 = a2b2
    f32m.add(d0, d3, t0)
    c0 = t0
    f32m.add(d1, d3, c1)
    f32m.add(c1, d4, c1)
    f32m.add(d2, d4, t1)
    c2 = t1
    return [c0, c1, c2]

def cubic(a):
    '''cubic in GF(3^{6*m})

    :param a: the operand
    :type a: list
    :returns: list, $a^3 \in GF(3^{6*m})$
    
    '''
    a0, a1, a2 = a
    a03 = f32m.cubic(a0)
    a13 = f32m.cubic(a1)
    a23 = f32m.cubic(a2)
    f32m.add(a03, a13, a03)
    f32m.add(a03, a23, a03)
    c0 = a03
    f32m.sub(a13, a23, a13)
    c1 = a13
    c2 = a23
    return [c0, c1, c2]

def power(a, n):
    '''power in GF(3^{6*m})

    :param a: the operand
    :type a: list
    :param n: the order of power
    :type n: int
    :returns: list, $a^n \in GF(3^{6*m})$
    
    '''
    result = one()
    while n > 0:
        if n % 2 == 1:
            result = mult(a, result)
        a = mult(a, a)
        n //= 2
    return result

