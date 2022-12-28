from tate_bilinear_pairing import f3m
from tate_bilinear_pairing import f33m
import unittest

class Test(unittest.TestCase):
    def test_mult(self):
        # (1+x*p+(x+1)*p^2) * (x+2+(x^2+1)*p+(x^2+2)*p^2)
        # 2*p^2*x^3 + p*x^2 + 2*x^3 + p*x + x^2 + p + x
        f3m._set_param(4, 1)
        a = [f3m._E([1]), f3m._E([0, 1]), f3m._E([1, 1])]
        b = [f3m._E([2, 1]), f3m._E([1, 0, 1]), f3m._E([2, 0, 1])]
        c = f33m.mult(a, b)
        assert c == [  f3m._E([0, 1, 1, 2]),
                       f3m._E([1, 1, 1]),
                       f3m._E([0, 0, 0, 2]) ]

    def test_inverse(self):
        f3m._set_param(5, 4)
        # the inversion of 2*x^2+2*x+1 is x^4 + 2*x^3 + x^2 + x, mod x^5+x^4+2
        a = [f3m._E([1, 2, 2]), f3m.zero(), f3m.zero()]
        b = [f3m._E([0, 1, 1, 2, 1]), f3m.zero(), f3m.zero()]
        assert f33m.inverse(a) == b

        f3m._set_param(4, 1)
        # the inversion of 1+(x+1)*p+x*p^2 is (2*x^2)*p^2+(x^3+x+1)*p+x^3, mod x^4+x+2
        a = [f3m._E([1]), f3m._E([1, 1]), f3m._E([0, 1])]
        b = [f3m._E([0, 0, 0, 1]), f3m._E([1, 1, 0, 1]), f3m._E([0, 0, 2])]
        assert f33m.inverse(a) == b

        # the inversion of 1+x*p+(x+1)*p^2 is (2*x^3+x)*p^2+(2*x^2+x+2)*p+x^3+2*x^2+2*x, mod x^4+x+2
        a = [f3m._E([1]), f3m._E([0, 1]), f3m._E([1, 1])]
        b = [f3m._E([0, 2, 2, 1]), f3m._E([2, 1, 2]), f3m._E([0, 1, 0, 2])]
        assert f33m.inverse(a) == b
        
