from tate_bilinear_pairing import ecc, eta, f3m
import unittest

class Test(unittest.TestCase):
    def setUp(self):
        ecc.f3m._set_param(5, 4)

    def test_order(self):
        ecc.f3m._set_param(97, 12)
        eta.init(151)
        p = ecc.gen()
        a = ecc.scalar_mult(ecc.order(), p)
        self.assertTrue(a[0])
                
    def test_add(self):
        # inf + inf == inf
        a = ecc.inf()
        b = ecc.inf()
        assert ecc.add(a, b)[0]
        # inf + p == p, p + inf == p
        a = [False, f3m.random(), f3m.random()]
        b = ecc.inf()
        assert ecc.add(a, b) == a
        assert ecc.add(b, a) == a
        # (0,1) + (0,2) == inf
        a = [False, f3m.zero(), f3m.one()]
        b = [False, f3m.zero(), f3m._E([2])]
        assert ecc.add(a, b)[0]
        # (0,1) + (1,1) == (2,2)
        # (1,1) + (1,1) == (2,1)
        # (0,1) + (0,1) == (1,1)
        for ax, ay, bx, by, cx, cy in [(0, 1, 1, 1, 2, 2), (1, 1, 1, 1, 2, 1), (0, 1, 0, 1, 1, 1)]:
            a = [False, f3m._E([ax]), f3m._E([ay])]
            b = [False, f3m._E([bx]), f3m._E([by])]
            c = [False, f3m._E([cx]), f3m._E([cy])]
            assert ecc.add(a, b) == c
            assert ecc.add(b, a) == c
        # P=E2(a^2 + a + 2 , a^4 + a^2 ) 
        # Q=E2(a^3 + a^2 + 1 , 2*a^4 + a + 1 )
        # P+Q == (2*a^4 + 2*a^3 + a^2 : 2*a^3 + a + 1)
        a = [False, f3m._E([2, 1, 1]), f3m._E([0, 0, 1, 0, 1])]
        b = [False, f3m._E([1, 0, 1, 1]), f3m._E([1, 1, 0, 0, 2])]
        c = [False, f3m._E([0, 0, 1, 2, 2]), f3m._E([1, 1, 0, 2, 0])]
        assert ecc.add(a, b) == c

    def test_scalar_mult(self):
        p = [False, f3m.zero(), f3m.one()]
        # 0 * (0,1) == inf
        assert ecc.scalar_mult(0, p)[0]
        # 1 * (0,1) == (0,1)
        assert ecc.scalar_mult(1, p) == p
        # 2 * (0,1) == (1,1)
        c = [False, f3m.one(), f3m.one()]
        assert ecc.scalar_mult(2, p) == c
        # 3 * (0,1) == (2,2)
        c = [False, f3m._E([2]), f3m._E([2])]
        assert ecc.scalar_mult(3, p) == c
        # 4 * (0,1) == (2,1)
        c = [False, f3m._E([2]), f3m.one()]
        assert ecc.scalar_mult(4, p) == c
        
        f3m._set_param(97, 12)
        eta.init(151)
        g = ecc.gen()
        v1 = ecc.scalar_mult(3, g)
        v2 = ecc.add(g, g)
        v2 = ecc.add(v2, g)
        self.assertEqual(v1, v2)
