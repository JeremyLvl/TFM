from tate_bilinear_pairing import f3m
import unittest

class TestF3(unittest.TestCase):
    def testmult(self):
        for a, b, c in (
                        [0, 0, 0],
                        [0, 1, 0],
                        [0, 2, 0],
                        [1, 0, 0],
                        [1, 1, 1],
                        [1, 2, 2],
                        [2, 0, 0],
                        [2, 1, 2],
                        [2, 2, 1],
                        ):
            assert f3m._f3mult(a, b) == c

def in_f3m(a):
    assert type(a) == list
    assert len(a) == 2
    assert len(a[0]) == len(a[1]) == f3m._ln
    return True

class TestF3M(unittest.TestCase):
    def test_param(self):
        if f3m._W == 31:
            f3m._set_param(2, 1) # erase
            f3m._set_param(97, 12)
            assert f3m._m == 97
            assert f3m._ln == 4
            assert f3m._p == [[4096, 0, 0, 16], [1, 0, 0, 0]]
    
    def test_hex(self):
        f3m._set_param(5, 4)
        a = f3m._E([0])
        assert f3m._hex(a) == '000'
        a = f3m._E([1])
        assert f3m._hex(a) == '001'
        a = f3m._E([2])
        assert f3m._hex(a) == '002'
        a = f3m._E([0,2])
        assert f3m._hex(a) == '008'
        a = f3m._E([0,0,2])
        assert f3m._hex(a) == '020'
    
    def test_shift_down(self):
        if f3m._W == 31:
            a = [0x40000001, 1]
            f3m._shift_down(a)
            assert a == [0x60000000, 0]
            
            a = [0,0,0,0,1]
            for _ in range(100):
                f3m._shift_down(a)
            for _ in range(100):
                f3m._shift_up(a)
            assert a == [0,0,0,0,1]
    
            a = [8388608, 4]
            for _ in range(21):
                f3m._shift_down(a)
            self.assertEqual(a, [0x1004, 0])
    
    def test_shift_up(self):
        if f3m._W == 31:
            a = [0x40000000, 0x40000000]
            f3m._shift_up(a)
            assert a == [0, 1]

    def test_get(self):
        if f3m._W == 31:
            a = [[0x55555555, 0x2AAAAAAA], [0x2AAAAAAA, 0x55555555]]
            for i in range(0, 62, 2):
                assert 1 == f3m._get(a, i)
            for i in range(1, 62, 2):
                assert 2 == f3m._get(a, i)

            a = [[0x55555555, 0x2AAAAAAA], [0, 0]]
            for i in range(0, 62, 2):
                assert 1 == f3m._get(a, i)
            for i in range(1, 62, 2):
                assert 0 == f3m._get(a, i)

            a = [[0, 0], [0x55555555, 0x2AAAAAAA]]
            for i in range(0, 62, 2):
                assert 2 == f3m._get(a, i)
            for i in range(1, 62, 2):
                assert 0 == f3m._get(a, i)
    
    def test_set(self):
        if f3m._W == 31:
            a = [[0,0], [0,0]]
            for i in range(0, 62, 2):
                f3m._set(a[0], i)
            for i in range(1, 62, 2):
                f3m._set(a[1], i)
            assert a == [[0x55555555, 0x2AAAAAAA], [0x2AAAAAAA, 0x55555555]]

    def test_clr(self):
        if f3m._W == 31:
            a = [[0x7FFFFFFF,0x7FFFFFFF], [0x7FFFFFFF,0x7FFFFFFF]]
            for i in range(0, 62, 2):
                f3m._clr(a[0], i)
            for i in range(1, 62, 2):
                f3m._clr(a[1], i)
            assert a == [[0x2AAAAAAA, 0x55555555], [0x55555555, 0x2AAAAAAA]]
    
    def test_random(self):
        f3m._set_param(97, 12)
        f3m.random() # TODO: accurate test method
    
    def test_add(self):
        f3m._set_param(4, 1)
        a = f3m._E([0,1,0,0])
        b = f3m._E([0,0,0,2])
        f3m.add(a, b, a)
        assert a == f3m._E([0, 1, 0, 2])
        
    def test_add1(self):
        f3m._set_param(4, 1)
        a = f3m._E([1,1,0,0])
        f3m._add1(a)
        assert a == f3m._E([2, 1, 0, 0])

        f3m._set_param(97, 12)
        a = f3m.random()
        b = f3m.one()
        c = f3m.zero()
        f3m.add(a,b,c)
        f3m._add1(a)
        assert a == c

    def test_add2(self):
        f3m._set_param(4, 1)
        a = f3m._E([1,1,0,0])
        f3m._add2(a)
        assert a == f3m._E([0, 1, 0, 0])

        f3m._set_param(97, 12)
        a = f3m.random()
        b = f3m.one()
        c = f3m.zero()
        f3m.sub(a,b,c)
        f3m._add2(a)
        assert a == c

    def test_neg(self):
        f3m._set_param(4, 1)
        a = f3m._E([0,1,0,2])
        f3m.neg(a, a)
        assert a == f3m._E([0, 2, 0, 1])

    def test_sub(self):
        f3m._set_param(4, 1)
        a = f3m._E([2, 0, 0, 0])
        b = f3m._E([0, 1, 0, 0])
        f3m.sub(a, b, a)
        assert a == f3m._E([2, 2, 0, 0])

    def test_reduct(self):
        f3m._set_param(4, 1)
        a = f3m._E([0, 0, 2, 1, 2])
        f3m.reduct(5, a)
        assert a == f3m._E([2, 1, 2, 1])

        f3m._set_param(97, 12)
        a = f3m.random()
        b = f3m.zero()
        f3m.sub(a, f3m._p, b)
        f3m.reduct(97, b)
        assert b == a

    def test_f1(self):
        f3m._set_param(4, 1)
        a = f3m._E([0, 1, 0, 2])
        b = f3m.zero()
        f3m._f1(2, a, b)
        assert b == f3m._E([0, 2, 0, 1])
        f3m._f1(1, a, b)
        assert b == a
        f3m._f1(0, a, b)
        assert b == f3m.zero()
    
    def test_f2(self):
        f3m._set_param(4, 1)
        a = f3m._E([1, 0, 0, 1]) # 1 + x^3
        f3m._f2(a)
        assert a == f3m._E([1])
        a = f3m._E([1])
        f3m._f2(a)
        assert a == f3m._E([0,1])

    def test_mult(self):
        f3m._set_param(2, 1)
        a = f3m._E([0, 1])
        b = f3m._E([0, 1])
        assert f3m.mult(a, b) == f3m._E([1, 2])
        
        a = f3m._E([1, 1])
        b = f3m._E([0, 1])
        assert f3m.mult(a, b) == f3m._E([1, 0])
        
    def test_cubic(self):
        f3m._set_param(5, 4)
        a = f3m._E([0, 1, 1, 2, 1])
        b = f3m.cubic(a)
        assert b == f3m._E([0, 1, 2, 0, 1])
        
        f3m._set_param(97, 12)
        a = f3m.random()
        b = f3m.mult(a, a)
        b = f3m.mult(b, a)
        c = f3m.cubic(a)
        self.assertEqual(b, c)
        
    def test_inverse(self):
        f3m._set_param(4, 1)
        a_list = ([1, 1], [1, 1, 1], [1, 1, 1, 1], [1], [2],)
        a_inv_list = ([0, 1, 2, 1], [1, 0, 1, 2], [0, 0, 0, 1], [1], [2],)
        for a, a_inv in zip(a_list, a_inv_list):
            a1 = f3m.inverse(f3m._E(a))
            a2 = f3m._E(a_inv)
            assert a1 == a2
    
        for _ in range(10):
            a = f3m.random()
            b = f3m.inverse(a)
            c = f3m.mult(a, b)
            assert c == f3m.one()
