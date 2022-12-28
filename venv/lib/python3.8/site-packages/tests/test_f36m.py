from tate_bilinear_pairing import f36m
from tate_bilinear_pairing import f3m
import unittest

class Test(unittest.TestCase):
    def test_power(self):
        f3m._set_param(5, 4)
        a = f36m.random()
        n = 100
        b = f36m.power(a, n)
        c = f36m.one()
        for _ in range(n):
            c = f36m.mult(c, a)
        self.assertEqual(c, b)
        
    def test_cubic(self):
        # the cubic of 1+(x+1)\sigma +[x^2+(x^2+x)\sigma]\rho +[2x^2+(2x^2+1)\sigma]\rho^2 is
        # 1 +(1+x^3)\sigma +2x^6\ +(1+2x^3+x^6)\sigma\rho + 2x^6\rho^2 +(2+x^6)\rho^2\sigma
        f3m._set_param(97, 12)
        _0 = [f3m._E([1]), f3m._E([1, 1])]
        _1 = [f3m._E([0, 0, 1]), f3m._E([0, 1, 1])]
        _2 = [f3m._E([0, 0, 2]), f3m._E([1, 0, 2])]
        a = [_0, _1, _2]
        c = f36m.cubic(a)
        _0 = [f3m._E([1]),
              f3m._E([1, 0, 0, 1])]
        _1 = [f3m._E([0, 0, 0, 0, 0, 0, 2]),
              f3m._E([1, 0, 0, 2, 0, 0, 1])]
        _2 = [f3m._E([0, 0, 0, 0, 0, 0, 2]),
              f3m._E([2, 0, 0, 0, 0, 0, 1])]
        b = [_0, _1, _2]
        self.assertEqual(b, c)
    
    def test_mult(self):
        f3m._set_param(5, 4)
        # the square of 2*p^2+(2*x^3+x)*p+x^4*s+x^4+2*x^2+2*x+1 is
        # (x^4*s+1)*p^2+((x^2+2*x)*s+x^3+2*x^2+2*x)*p+(x^4+2*x^3+x^2+1)*s+x^3+2*x^2+1
        _2 = [f3m._E([2]), f3m.zero()]
        _1 = [f3m._E([0, 1, 0, 2]), f3m.zero()]
        _0 = [f3m._E([1, 2, 2, 0, 1]), f3m._E([0, 0, 0, 0, 1])]
        a = [_0, _1, _2]
        _2 = [f3m._E([2]), f3m.zero()]
        _1 = [f3m._E([0, 1, 0, 2]), f3m.zero()]
        _0 = [f3m._E([1, 2, 2, 0, 1]), f3m._E([0, 0, 0, 0, 1])]
        a2 = [_0, _1, _2]
        _2 = [f3m._E([1]), f3m._E([0, 0, 0, 0, 1])]
        _1 = [f3m._E([0, 2, 2, 1]), f3m._E([0, 2, 1])]
        _0 = [f3m._E([1, 0, 2, 1]), f3m._E([1, 0, 1, 2, 1])]
        b = [_0, _1, _2]
        self.assertEqual(f36m.mult(a, a2), b)
        
        # the cubic of 1+(x+1)\sigma +[x^2+(x^2+x)\sigma]\rho +[2x^2+(2x^2+1)\sigma]\rho^2 is
        # 1 +(1+x^3)\sigma +2x^6\rho +(1+2x^3+x^6)\sigma\rho + 2x^6\rho^2 +(2+x^6)\rho^2\sigma
        f3m._set_param(97, 12)
        _0 = [f3m._E([1]), f3m._E([1, 1])]
        _1 = [f3m._E([0, 0, 1]), f3m._E([0, 1, 1])]
        _2 = [f3m._E([0, 0, 2]), f3m._E([1, 0, 2])]
        a = [_0, _1, _2]
        _0 = [f3m._E([1]), f3m._E([1, 1])]
        _1 = [f3m._E([0, 0, 1]), f3m._E([0, 1, 1])]
        _2 = [f3m._E([0, 0, 2]), f3m._E([1, 0, 2])]
        a2 = [_0, _1, _2]
        c = f36m.mult(a, a2)
        c = f36m.mult(a2, c)
        _0 = [f3m._E([1]),
              f3m._E([1, 0, 0, 1])]
        _1 = [f3m._E([0, 0, 0, 0, 0, 0, 2]),
              f3m._E([1, 0, 0, 2, 0, 0, 1])]
        _2 = [f3m._E([0, 0, 0, 0, 0, 0, 2]),
              f3m._E([2, 0, 0, 0, 0, 0, 1])]
        b = [_0, _1, _2]
        self.assertEqual(b, c)
