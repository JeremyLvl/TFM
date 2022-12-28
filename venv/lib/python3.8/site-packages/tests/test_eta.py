from tate_bilinear_pairing import f36m, f3m, ecc, eta
import unittest

class Test(unittest.TestCase):
    def test_algo4a(self):
        eta.init(151)
        t = f3m.random()
        u = f3m.random()
        c = eta._algo4a(t, u)
        nt = f3m._E()
        f3m.neg(t, nt) # nt == -t
        nt2 = f3m.mult(t, nt) # nt2 == -t^2
        a = [[nt2, u], [nt, f3m.zero()], [f3m.two(), f3m.zero()]] # a == (-t^2 +u*s -t*p -p^2)
        b = f36m.cubic(a)
        self.assertEqual(b, c)

    def test_algo5(self):
        eta.init(151)
        g = ecc.gen()
        w1 = eta._algo4(g[1], g[2], g[1], g[2])
        v1 = eta._algo5(g[1], g[2], g[1], g[2])
        self.assertEqual(w1, v1)

    def test_pairing(self):
        'test bilinear of the pairing'
        eta.init(151)
        g = ecc.gen()
        v1 = eta.pairing(g[1], g[2], g[1], g[2])
        p = ecc.scalar_mult(3, g)
        v1 = f36m.power(v1, 3)
        v2 = eta.pairing(p[1], p[2], g[1], g[2])
        self.assertEqual(v2, v1)

    def test_algo6(self):
        'computation of $U ^ {3^{3m} - 1}$'
        # a = x*s+x+1
        # a^(3^15-1) == (x^4 + 2*x^3 + x^2 + x + 2)*s + x^3 + x + 2
        eta.f3m._set_param(5, 4)
        a = [[f3m._E([1, 1]), f3m._E([0, 1])], [f3m.zero(), f3m.zero()], [f3m.zero(), f3m.zero()]]
        v = eta._algo6(a)
        w = [[f3m._E([2, 1, 0, 1]), f3m._E([2, 1, 1, 2, 1])], [f3m.zero(), f3m.zero()], [f3m.zero(), f3m.zero()]]
        assert w == v
        
        m = 7
        eta.f3m._set_param(m, 2)
        a = f36m.random()
        n = 3 ** (3 * m) - 1
        v1 = eta._algo6(a)
        v2 = f36m.power(a, n)
        assert v1 == v2
    
    def test_algo7(self):
        'computation of $U ^ {3^m+1}$, $U \in T_2(F_{3^3M})$'
        m = 7
        eta.f3m._set_param(m, 2)
        a = f36m.random()
        n = 3 ** (3 * m) - 1 # putting a into T_2(F_33m)
        a = f36m.power(a, n)
        n = 3 ** m + 1
        c = f36m.power(a, n)
        b = eta._algo7(a)
        self.assertEqual(b, c)
    
    def test_algo8(self):
        'computing U^M, M=(3^{3m}-1)*(3^m+1)*(3^m+1-\mu*b*3^{(m+1)//2})'
        m = 5
        eta.f3m._set_param(m, 4)
        a = f36m.random()
        v1 = eta._algo8(a)
        n = 3 ** (3 * m) - 1
        a = f36m.power(a, n) # putting a into T_2(F_33m)
        x = 3 ** m + 1
        if m % 12 in [1, 11]:
            y = x - 3 ** ((m + 1) // 2)
        else:
            y = x + 3 ** ((m + 1) // 2)
        n = x * y
        v2 = f36m.power(a, n)
        self.assertEqual(v1, v2)
        
        m = 13
        eta.f3m._set_param(m, 4)
        a = f36m.random()
        v1 = eta._algo8(a)
        n = 3 ** (3 * m) - 1
        a = f36m.power(a, n) # putting a into T_2(F_33m)
        x = 3 ** m + 1
        if m % 12 in [1, 11]:
            y = x - 3 ** ((m + 1) // 2)
        else:
            y = x + 3 ** ((m + 1) // 2)
        n = x * y
        v2 = f36m.power(a, n)
        self.assertEqual(v1, v2)

    def test_init(self):
        i = 0
        for p in eta._params:
            bit_num = int(p.split()[2])
            eta.init(bit_num)
            gen = ecc.gen()
            order = ecc.order()
            self.assertTrue(ecc.scalar_mult(order, gen)[0])
            i += 1
            if i == 10: break
