"""
This module is about point addition and point scalar multiplication on the elliptic curve $y^2=x^3-x+1$ over $GF(3^m)$.
Each element in the elliptic curve is expressed by a list of $[(bool)b, (list)x, (list)y]$.
If the value of $b$ is "True", it will mean the element is the point at infinity.
Otherwise, the value of $x$ and $y$ must obey $y^2=x^3-x+1$.
"""

from . import f3m
import random as _r

_order = None
_x = None
_y = None

def inf():
    'the point at infinity'
    return [True, f3m.zero(), f3m.zero()]

def _inf4():
    return [True, f3m.zero(), f3m.zero(), f3m.zero()]

def _clone(p):
    '_clone an elliptic curve group element'
    return [p[0], f3m._clone(p[1]), f3m._clone(p[2])]

def _clone4(p):
    return [p[0], f3m._clone(p[1]), f3m._clone(p[2]), f3m._clone(p[3])]

def gen():
    'generator in the elliptic curve group'
    return _clone([False, _x, _y])

def order():
    'the least number $k$ such that $k\cdot gen$ is inf in the elliptic curve group'
    return _order

def random():
    'a random point in the elliptic curve group'
    a = _r.randint(1, order())
    return scalar_mult(a, gen())

def _affine_to_proj(p):
    return p[:] + [f3m.one()]

def _proj_to_affine(p):
    ''' projective coordinate to affine coordinate
        (X, Y, Z) -> (X / (Z^2), Y / (Z^3))'''
    isinf, x, y, z = p
    if isinf or z == f3m.one():
        return _clone([isinf, x, y])
    t = f3m.inverse(z)
    t2 = f3m.mult(t, t)
    x = f3m.mult(x, t2)
    t2 = f3m.cubic(t)
    y = f3m.mult(y, t2)
    return [isinf, x, y]

def _double(p):
    'point double in projective coordinate'
    inf1, x1, y1, z1 = p
    if inf1:
        return _inf4()
    l1 = f3m.cubic(z1)
    l1 = f3m.mult(z1, l1)
    f3m.neg(l1, l1)
    z3 = f3m.mult(y1, z1)
    f3m.neg(z3, z3)
    l2 = f3m.mult(y1, y1)
    l2 = f3m.mult(l2, x1)
    x3 = f3m.mult(l1, l1)
    f3m.add(x3, l2, x3)
    l3 = f3m.cubic(y1)
    l3 = f3m.mult(l3, y1)
    f3m.neg(l3, l3)
    y3 = f3m.zero()
    f3m.sub(l2, x3, y3)
    y3 = f3m.mult(y3, l1)
    f3m.sub(y3, l3, y3)
    return [False, x3, y3, z3]

def _add(p1, p2):
    'point addition in projective coordinate'
    inf1, x1, y1, z1 = p1
    inf2, x2, y2, z2 = p2
    if inf1:
        return _clone4(p2)
    if inf2:
        return _clone4(p1)
    l1 = f3m.mult(x1, z2)
    l1 = f3m.mult(z2, l1)
    l2 = f3m.mult(x2, z1)
    l2 = f3m.mult(z1, l2)
    if l1 == l2: # X1 / Z1^2 == X2 / Z2^2
        l1 = f3m.cubic(z2)
        l1 = f3m.mult(y1, l1)
        l2 = f3m.cubic(z1)
        l2 = f3m.mult(y2, l2)
        if l1 == l2: # Y1 / Z1^3 == Y2 / Z2^3
            # point double
            return _double(p1)
        else:
            return _inf4()
    else:
        # P1 != P2 && P1 != - P2
        l1 = f3m.mult(z2, z2)
        l1 = f3m.mult(l1, x1)
        l2 = f3m.mult(z1, z1)
        l2 = f3m.mult(l2, x2)
        l3 = f3m.zero()
        f3m.sub(l1, l2, l3)
        l4 = f3m.cubic(z2)
        l4 = f3m.mult(l4, y1)
        l5 = f3m.cubic(z1)
        l5 = f3m.mult(l5, y2)
        l6 = f3m.zero()
        f3m.sub(l4, l5, l6)
        l7 = f3m.zero()
        f3m.add(l1, l2, l7)
        l8 = f3m.zero()
        f3m.add(l4, l5, l8)
        z3 = f3m.mult(z1, z2)
        z3 = f3m.mult(z3, l3)
        x3 = f3m.mult(l3, l3)
        x3 = f3m.mult(x3, l7)
        l1 = f3m.mult(l6, l6)
        f3m.sub(l1, x3, x3)
        y3 = f3m.cubic(l3)
        y3 = f3m.mult(y3, l8)
        l1 = f3m.cubic(l6)
        f3m.sub(y3, l1, y3)
        return [False, x3, y3, z3]

def add(p1, p2):
    'adding two elements in the elliptic curve group'
    p3 = _add(_affine_to_proj(p1), _affine_to_proj(p2))
    return _proj_to_affine(p3)
    
def scalar_mult(n, p):
    '''computing the scalar multiplication $n*p$, where $p$ is a point on the elliptic curve,
    and $n$ is an integer scalar value.'''
    a = _inf4()
    x = _clone4(_affine_to_proj(p))
    while n > 0:
        if (n & 1):
            a = _add(a, x)
        n = n // 2
        x = _double(x)
    return _proj_to_affine(a)
