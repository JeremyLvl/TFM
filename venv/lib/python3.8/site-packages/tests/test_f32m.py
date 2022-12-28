from tate_bilinear_pairing import f32m
import unittest

f3m = f32m.f3m

class Test(unittest.TestCase):
    def test_mult(self):
        # the square of (x^4*s+x^4+2*x^2+2*x+1) is (x^4+2*x^3+x^2+1)*s+2*x^3+2*x^2+2*x+1, mod x^5+x^4+2
        f3m._set_param(5, 4)
        a = [f3m._E([1, 2, 2, 0, 1]), f3m._E([0, 0, 0, 0, 1])]
        b = [f3m._E([1, 2, 2, 2, 0]), f3m._E([1, 0, 1, 2, 1])]
        self.assertEqual(f32m.mult(a, a), b)
