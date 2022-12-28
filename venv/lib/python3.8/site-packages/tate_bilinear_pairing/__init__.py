'''
Introduction

This package is a Python library for calculating Tate bilinear pairing, 
especially on super-singular elliptic curve $E:y^2=x^3-x+1$ in affine 
coordinates defined over a Galois Field $GF(3^m)$.

This package is also for calculating the addition of two elements 
in the elliptic curve group, and the addition of $k$ identical element 
in the elliptic curve group.

The code of this package for computing the Tate bilinear pairing follows 
the paper by Beuchat et al [3]. The code of this package for computing 
the elliptic curve group operation follows the paper by Kerins et al [2].

This package is in PURE Python, working with Python 2.7 and 3.2.

This package computes one Tate bilinear pairing within 3.26 seconds 
@ Intel Core2 L7500 CPU (1.60GHz).

=================================================

What is Tate bilinear pairing

Generally speaking, The Tate bilinear pairing algorithm is a transformation 
that takes two points on an elliptic curve and outputs a nonzero element 
in the extension field $GF(3^{6m})$. The state-of-the-art way of computing 
the Tate bilinear pairing is eta pairing, introduced by Barreto et al [4]. 
For more information, please refer to [1,2,3,4].

=================================================

Usage 1: calculating Tate bilinear pairing

Given two random numbers like this:

>>> import random
>>> a = random.randint(0,1000)
>>> b = random.randint(0,1000)

Computing two elements $[inf1, x1, y1]$, and $[inf2, x2, y2]$ in 
the elliptic curve group:

>>> from tate_bilinear_pairing import ecc
>>> g = ecc.gen()
>>> inf1, x1, y1 = ecc.scalar_mult(a, g)
>>> inf2, x2, y2 = ecc.scalar_mult(b, g)

Tate bilinear pairing is done via:

>>> from tate_bilinear_pairing import eta
>>> t = eta.pairing(x1, y1, x2, y2)

=================================================

Usage 2: calculating the addition of two elements in the elliptic curve group

Given two elements $p1=[inf1, x1, y1]$, and $p2=[inf2, x2, y2]$ in the 
elliptic curve group, the addition is done via:

>>> p1 = [inf1, x1, y1]
>>> p2 = [inf2, x2, y2]
>>> p3 = ecc.add(p1, p2)

=================================================

Usage 3: calculating the addition of $k$ identical elements

Given a non-negative integer $k$ and an group element $p1=[inf1, x1, y1]$, 
$k \cdot p1$ is computed via:

>>> k = random.randint(0,1000)
>>> p3 = ecc.scalar_mult(k, p1)

=================================================

References

[1] I. Duursma, H.S. Lee. 
    Tate pairing implementation for hyper-elliptic curves $y^2=x^p-x+d$.
    Advances in Cryptology - Proc. ASIACRYPT ’03, pp. 111-123, 2003.
[2] T. Kerins, W.P. Marnane, E.M. Popovici, and P.S.L.M. Barreto.
    Efficient hardware for the Tate pairing calculation in characteristic three.
    Cryptographic Hardware and Embedded Systems - Proc. CHES ’05, pp. 412-426, 2005.
[3] J. Beuchat, N. Brisebarre, J. Detrey, E. Okamoto, M. Shirase, and T. Takagi. 
    Algorithms and Arithmetic Operators for Computing the $\eta_T$ Pairing in Characteristic Three.
    IEEE Transactions on Computers, Special Section on Special-Purpose Hardware for Cryptography and Cryptanalysis, vol. 57 no. 11 pp. 1454-1468, 2008.
[4] P.S.L.M. Barreto, S.D. Galbraith, C. O hEigeartaigh, and M. Scott,
    Efficient Pairing Computation on Supersingular Abelian Varieties.
    Designs, Codes and Cryptography, vol. 42, no. 3, pp. 239-271, Mar. 2007.
'''
