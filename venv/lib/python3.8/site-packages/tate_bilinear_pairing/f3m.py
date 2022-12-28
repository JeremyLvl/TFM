"""
This module provides operations over the Galois Field $GF(3^m)$, where $m$ is a user-specified parameter.
$GF(3^m)$ is an extension field of $GF(3)$, and the degree of the extension is $m$.
In this module, an element of $GF(3^m)$ is a list of length $m$, where each element is in $GF(3)$. 
"""

import random as _r

'how many GF(3) elements are in one native machine integer.'
_W = 63
# TODO: determine $_W$ by Python native integer length
'degree of the irreducible polynomial'
_m = None
'irreducible polynomial is $x^m + x^t + 2$'
_t = None
'''the number of native machine integers required to represent one GF(3^m) element,
assuming the machine word size is no less than 32.'''
_ln = None
'$_p$ is the irreducible polynomial'
_p = None

def _E(a = None):
    'only for unittest'
    c = zero()
    if a is not None:
        c1, c2 = c
        for i in range(len(a)):
            if a[i] == 1:
                _set(c1, i)
            elif a[i] == 2:
                _set(c2, i)
    return c

def _E2(a):
    'only for unittest'
    l = len(a)//2
    c1 = _E(a[:l])
    c2 = _E(a[l:])
    s = ','.join(map(str, c1[0]+c1[1]+c2[0]+c2[1]))
    print('={%s};' % s)

def _E3(a):
    'only for unittest'
    l = len(a)//3
    c1 = _E(a[:l])
    c2 = _E(a[l:2*l])
    c3 = _E(a[2*l:])
    s = ','.join(map(str, c1[0]+c1[1]+c2[0]+c2[1]+c3[0]+c3[1]))
    print('={%s};' % s)

def _E6(a):
    'only for unittest'
    l = len(a)//6
    c1 = _E(a[:l])
    c2 = _E(a[l:2*l])
    c3 = _E(a[2*l:3*l])
    c4 = _E(a[3*l:4*l])
    c5 = _E(a[4*l:5*l])
    c6 = _E(a[5*l:])
    s = ','.join(map(str, c1[0]+c1[1]+c2[0]+c2[1]+c3[0]+c3[1]+
                          c4[0]+c4[1]+c5[0]+c5[1]+c6[0]+c6[1]))
    print('={%s};' % s)

def _hex(a):
    'convert an GF(3^m) element to hex integer'
    def f(a, b):
        return str({0:0, 1:1, 2:2, 10:4, 11:5, 12:6, 20:8, 21:9, 22:'a'}[a*10+b])
    l = [_get(a, i) for i in range(_m)] + [0] * (_m%2)
    l.reverse()
    x = [f(l[i],l[i+1]) for i in range(0,len(l),2)]
    return ''.join(x)

def _set_param(m, t):
    'set the irreducible polynomial as $x^m + x^t + 2$'
    global _m, _t, _ln, _p
    _m = m
    _t = t
    _ln = (_m + (_W - 1) + 1) // _W # extra one bit for $_p$
    # assign $_p$
    _p1 = [0] * _ln
    _p2 = [0] * _ln
    _p2[0] = 1 # _p == x^m+x^t+2
    _p1[t // _W] |= 1 << (t % _W)
    _p1[m // _W] |= 1 << (m % _W)
    _p = [_p1, _p2]

def _clone(a):
    return [a[0][:], a[1][:]]

def _shift_down(a):
    'a <- a/x'
    h = 0
    x = 1 << (_W-1)
    for i in range(len(a) - 1, -1, -1):
        l = a[i] & 1
        a[i] >>= 1
        if h: 
            a[i] |= x
        h = l

def _shift_up(a):
    'a <- a*x'
    l = 0
    x = 1 << (_W-1)
    y = x - 1
    for i in range(len(a)):
        h = a[i] & x
        a[i] = ((a[i] & y) << 1) | l
        if h: l = 1
        else: l = 0

def _get(a, pos):
    'return the coefficient of $x^pos$ in $a$'
    x = pos // _W
    y = 1 << (pos % _W)
    a1 = a[0][x] & y
    a2 = a[1][x] & y
    if a1:
        z = 1
    elif a2:
        z = 2
    else:
        z = 0
    return z

def _set(a, pos):
    'set the coefficient of $x^pos$ as 1'
    a[pos // _W] |= 1 << (pos % _W)

def _clr(a, pos):
    'set the coefficient of $x^pos$ as 0'
    a[pos // _W] &= ~(1 << (pos % _W))

def zero():
    'returning the zero element in $GF(3^m)$'
    return [[0] * _ln, [0] * _ln]

def one():
    'returning the element with value of one in $GF(3^m)$'
    x = [0] * _ln
    x[0] = 1
    return [x, [0] * _ln]

def two():
    'returning the element with value of two in $GF(3^m)$'
    x = [0] * _ln
    x[0] = 1
    return [[0] * _ln, x]

def random():
    'returning a random element in $GF(3^m)$'
    rm = _m % _W
    i1 = (1 << _W) - 1
    i2 = (1 << rm) - 1
    a1 = [0] * _ln
    a2 = [0] * _ln
    for i in range(_ln - 1):
        a1[i] = _r.randint(0, i1)
        a2[i] = _r.randint(0, i1)
    if rm: x = i2
    else: x = i1
    a1[_ln - 1] = _r.randint(0, x)
    a2[_ln - 1] = _r.randint(0, x)
    for i in range(_ln): # assuring there is no bit that a1[x] & a2[x] == 1
        a2[i] &= ~a1[i] # TODO: this is not uniform distribution
    return [a1, a2]

def add(a, b, c):
    '''doing addition
    The function sets the value of $c$ as $a+b$, and returns nothing.
    $ln$ equals the number of native integers of $a$.'''
    aa1, aa2 = a
    bb1, bb2 = b
    for i in range(len(a[0])):
        a1 = aa1[i]
        a2 = aa2[i]
        b1 = bb1[i]
        b2 = bb2[i]
        t = (a1 | b2) ^ (a2 | b1)
        c[0][i] = (a2 | b2) ^ t
        c[1][i] = (a1 | b1) ^ t

def _add1(a):
    'a <- a+1'
    a1 = a[0][0]
    a2 = a[1][0]
    b1 = 1
    b2 = 0
    t = (a1 | b2) ^ (a2 | b1)
    a[0][0] = (a2 | b2) ^ t
    a[1][0] = (a1 | b1) ^ t

def _add2(a):
    'a <- a+2'
    a1 = a[0][0]
    a2 = a[1][0]
    b1 = 0
    b2 = 1
    t = (a1 | b2) ^ (a2 | b1)
    a[0][0] = (a2 | b2) ^ t
    a[1][0] = (a1 | b1) ^ t

def neg(a, c):
    '''doing negation
    The functions sets the value of $c$ as $-a$ and returns nothing.'''
    if c is a:
        a[0], a[1] = a[1], a[0]
    else:
        c[0][:] = a[1]
        c[1][:] = a[0]

def sub(a, b, c):
    '''doing subtraction
    note that $add$, $neg$, $sub$ are performed element-wisely.
    The function sets the value of $c$ as $a-b$, and returns nothing.
    $ln$ equals the number of native integers of $a$.'''
    aa1, aa2 = a
    bb2, bb1 = b
    for i in range(len(a[0])):
        a1 = aa1[i]
        a2 = aa2[i]
        b1 = bb1[i]
        b2 = bb2[i]
        t = (a1 | b2) ^ (a2 | b1)
        c[0][i] = (a2 | b2) ^ t
        c[1][i] = (a1 | b1) ^ t

def reduct(ln, a):
    '''doing reduction
    The function returns the value of $a$ modulo $the irreducible trinomial$.
    $ln$ equals the degree of $a$.'''
    p1 = [0] * len(a[0])
    p2 = [0] * len(a[0])
    _set(p1, ln)
    _set(p1, ln - _m + _t)
    _set(p2, ln - _m)
    p = [p1, p2]
    x = ln
    while x >= _m:
        v = _get(a, x)
        if v == 1:
            sub(a, p, a)
        elif v == 2:
            add(a, p, a)
        x -= 1
        _shift_down(p1)
        _shift_down(p2)

def _f1(number, a, c):
    '''doing multiplication of a constant $number$ and an element $a$ in GF(3^m)
    The function sets $c == number * a$ and returns nothing.'''
    if number == 0:
        l = len(a[0])
        c[0][:] = [0] * l
        c[1][:] = [0] * l
    elif number == 1:
        c[0][:] = a[0]
        c[1][:] = a[1]
    else:
        c[0][:] = a[1]
        c[1][:] = a[0]

def _f2(a):
    '''multiply $a$ by $x$ then doing a reduction'''    
    _shift_up(a[0])
    _shift_up(a[1])
    v = _get(a, _m)
    if v == 1:
        sub(a, _p, a)
    elif v == 2:
        add(a, _p, a)

def mult(a, b):
    '''doing multiplication in GF(3^m)
    The function returns $a*b \in GF(3^m)$'''
    a = _clone(a)
    c = zero()
    t = zero()
    for i in range(_m):
        v = _get(b, i)
        _f1(v, a, t) # t == b[i]*a in GF(3^m)
        add(c, t, c) # c += b[i]*a in GF(3^m)
        _f2(a) # a == a*x in GF(3^m)
    return c

def cubic(a):
    '''computing the cubic of an element $a$ in GF(3^m), and returning $a^3$'''
    # TODO: better algorithm
    l = (3 * _m - 2 + _W - 1) // _W
    b1 = [0] * l
    b2 = [0] * l
    b = [b1, b2]
    for i in range(_m):
        v = _get(a, i)
        if v == 1: _set(b1, 3 * i)
        elif v == 2: _set(b2, 3 * i)
    reduct(3 * _m - 3, b)
    del b1[_ln:]
    del b2[_ln:]
    return b

_list1 = (0, 1, 2, 0, 1)

def _f3mult(a, b):
    '''multiplication modulo 3 of two elements in GF(3)
    for example, $mult(2,2) == 1$, and $mult(1,2) == 2$'''
    return _list1[a * b]

def inverse(a):
    '''computing the inversion of an element $a$ in GF(3^m).
    The algorithm is by Tim Kerins, Emanuel Popovici and William Marnane
    in the paper of "Algorithms and Architectures for use in FPGA",
    Lecture Notes in Computer Science, 2004, Volume 3203/2004, 74-83.
    Note that $U$ must have an extra bit, i.e, (_m + _W - 1) // _W == (_m + _W) // _W
    '''
    S = _clone(_p) # S = p(x)
    extra = (3 * _m + _W - 1) // _W - _ln
    S[0] += [0] * extra # adding enough space, for shifting
    S[1] += [0] * extra
    R = _clone(a)
    R[0] += [0] * extra # keeping $R$ and $S$ at the same length
    R[1] += [0] * extra
    t = [[0] * len(S), [0] * len(S)] # at the same length as $S$
    U = zero()
    U[0][0] = 1 # U == 1
    V = zero()
    t2 = zero()
    d = 0
    for _ in range(2 * _m):
        r_m = _get(R, _m)
        s_m = _get(S, _m)
        if r_m == 0:
            _shift_up(R[0]) # R = xR
            _shift_up(R[1])
            _f2(U) # U = xU mod p
            d += 1
        else:
            q = _f3mult(r_m, s_m)
            _f1(q, R, t)
            sub(S, t, S) # S = S-qR
            _f1(q, U, t2)
            sub(V, t2, V) # V = V-qU
            _shift_up(S[0])
            _shift_up(S[1]) # S = xS
            if d == 0:
                R, S = S, R
                U, V = V, U
                _f2(U) # U = xU mod p
                d += 1
            else:
                x = _get(U, 0)
                if x == 1: # assuring x|U
                    add(U, _p, U)
                elif x == 2:
                    sub(U, _p, U)
                _shift_down(U[0])
                _shift_down(U[1]) # divide U by $x$
                d -= 1
    r_m = _get(R, _m)
    if r_m == 2:
        neg(U, U)
    # assert r_m is not zero
    return U

def _from_str(s):
    ret = zero()
    n = (_m + 7) // 8
    x = 0
    j = 0
    for i in range(n):
        c = int(s[j:j+2], 16)
        x |= c << (4 * j)
        j += 2
    for i in range(_ln):
        ret[0][i] = x & ((1 << _W) - 1)
        x >>= _W
    s = s[2*n:]
    x = 0
    j = 0
    for i in range(n):
        c = int(s[j:j+2], 16)
        x |= c << (4 * j)
        j += 2
    for i in range(_ln):
        ret[1][i] = x & ((1 << _W) - 1)
        x >>= _W
    return ret
