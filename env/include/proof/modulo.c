//@ #include "modulo.gh"

/*@

    lemma void div_mod(int g, int k, int l)
    requires g == (k % l) &*& l > 0;
    ensures (-l <= g) &*& (g < l);
    {
    div_rem(k, l);
    }

    lemma void div_mod_gt_0(int mod, int div, int whole)
    requires mod == (div % whole) &*& whole > 0 &*& div >= 0;
    ensures (0 <= mod) &*& (mod < whole);
    {
    div_rem(div, whole);
    }

    lemma void loop_lims(int k, int capacity)
    requires 0 < capacity;
    ensures 0 <= loop_fp(k, capacity) &*& loop_fp(k, capacity) < capacity;
    {
    div_rem(k, capacity);
    assert(-capacity <= k%capacity);
    assert(0 <= k%capacity + capacity);
    div_rem((k + capacity), capacity);
    assert(capacity > 0);
    div_rem(k%capacity + capacity, capacity);
    assert(0 <= ((k%capacity + capacity)%capacity));
    }

    lemma void quotidient_zero_pos(int a, int b, int q, int r)
    requires 0 <= a &*& a < b &*& 0 <= r &*& a == q * b + r &*& r < b;
    ensures q == 0;
    {
    if (q == 0) {
    } else if (0 <= q) {
        mul_mono(1, q, b);
    } else {
        mul_mono(q, -1, b);
    }
    }

    lemma void quotidient_zero_neg(int a, int b, int q, int r)
    requires -b < a &*& a <= 0 &*& -b < r &*& a == q * b + r &*& r <= 0;
    ensures q == 0;
    {
    if (q == 0) {
    } else if (0 <= q) {
        mul_mono(1, q, b);
    } else {
        mul_mono(q, -1, b);
    }
    }

    lemma void division_round_to_zero(int a, int b)
    requires -b < a &*& a < b;
    ensures a/b == 0;
    {
    div_rem(a, b);
    if (0 <= a)
    quotidient_zero_pos(a, b, a / b, a % b);
    else
    quotidient_zero_neg(a, b, a / b, a % b);
    }

    lemma void div_incr(int a, int b)
    requires 0 <= a &*& 0 < b;
    ensures true == ( (a+b)/b == a/b + 1 );
    {
    div_rem(a+b, b);
    if ((a+b)/b <= a/b) {
        div_rem(a, b);
        mul_mono((a+b)/b, a/b, b);
        assert false;
    }

    assert a/b + 1 <= (a+b)/b;
    assert 0 <= a;
    div_rem(a, b);
    if (a/b <= -1) {
        mul_mono(a/b, -1, b);
        assert(false);
    }
    assert 0 <= (a/b);
    if (a/b + 1 <= (a+b)/b - 1) {
        mul_mono(a/b + 1, (a+b)/b - 1, b);
        assert(false);
    }
    }

    lemma void loop_bijection(int k, int capacity)
    requires 0 <= k &*& k < capacity;
    ensures loop_fp(k, capacity) == k;
    {
    division_round_to_zero(k, capacity);
    div_rem(k, capacity);
    div_incr(k, capacity);
    div_rem((k + capacity), capacity);
    }

    lemma void mod_rotate(int a, int b)
    requires 0 <= a &*& 0 < b;
    ensures true == ((a+b)%b == a%b);
    {
    div_rem(a+b, b);
    div_rem(a, b);
    div_incr(a, b);
    mul_subst((a+b)/b, (a/b + 1), b);
    }

    lemma void loop_injection(int k, int capacity)
    requires 0 <= k &*& 0 < capacity;
    ensures loop_fp(k + capacity, capacity) == loop_fp(k, capacity);
    {
    mod_rotate(k, capacity);
    }

    lemma void loop_injection_minus_n(int k, int capacity, int n)
    requires 0 <= k &*& 0 < capacity &*& 0 <= k + n*capacity &*& n < 0;
    ensures loop_fp(k + n*capacity, capacity) == loop_fp(k, capacity);
    {
    int i = n;
    for (i = n; i < 0; ++i)
        invariant loop_fp(k + i*capacity, capacity) == loop_fp(k + n*capacity, capacity) &*&
                0 <= k + i*capacity &*&
                i <= 0;
        decreases -i;
    {
        mod_rotate(k + i*capacity, capacity);
        assert loop_fp(k + i*capacity, capacity) == loop_fp(k + n*capacity, capacity);
    }
    assert loop_fp(k + i*capacity, capacity) == loop_fp(k + n*capacity, capacity);
    }


    lemma void loop_injection_n(int k, int capacity, int n)
    requires 0 <= k &*& 0 < capacity &*& 0 <= k + n*capacity;
    ensures loop_fp(k + n*capacity, capacity) == loop_fp(k, capacity);
    {
    if (0 <= n) {
        for (int i = 0; i < n; ++i)
        invariant loop_fp(k + i*capacity, capacity) == loop_fp(k, capacity) &*&
                    0 <= k + i*capacity &*&
                    i <= n;
        decreases n-i;
        {
        mod_rotate(k + i*capacity, capacity);
        }
    } else {
        loop_injection_minus_n(k, capacity, n);
    }
    }

    lemma void loop_fixp(int k, int capacity)
    requires 0 <= k &*& 0 < capacity;
    ensures loop_fp(k, capacity) == loop_fp(loop_fp(k, capacity), capacity);
    {
    loop_lims(k, capacity);
    loop_bijection(loop_fp(k, capacity), capacity);
    }

    lemma void mod_bijection(int x, int y)
    requires -y < x &*& x < y;
    ensures x == x%y;
    {
    division_round_to_zero(x, y);
    div_rem(x, y);
    }

    lemma int loop_shift_inv(int x, int y, int capacity)
    requires 0 <= x &*& x < capacity &*& 0 <= y &*& y < capacity;
    ensures 0 <= result &*& result < capacity &*&
            loop_fp(result + y, capacity) == x;
    {
    int z = loop_fp(y - x, capacity);
    loop_lims(y - x, capacity);
    if (z == 0) {
        assert true == (((y-x)%capacity + capacity)%capacity == 0);
        div_rem(y-x, capacity);
        if (1 <= (y-x)%capacity) {
        mod_rotate((y-x)%capacity, capacity);
        assert true == (0 == ((y-x)%capacity%capacity));
        division_round_to_zero((y-x)%capacity, capacity);
        div_rem((y-x)%capacity, capacity);
        assert false;
        }

        if ((y-x)%capacity <= -1) {
        assert (-capacity < (y-x)%capacity);
        assert true == (0 <= (y-x)%capacity + capacity);
        division_round_to_zero((y-x)%capacity + capacity, capacity);
        mul_subst(((y-x)%capacity + capacity)/capacity, 0, capacity);
        assert true == (((y-x)%capacity + capacity)/capacity*capacity == 0);
        div_rem((y-x)%capacity + capacity, capacity);
        }
        assert true == ((y-x)%capacity == 0);//TADA!!!

        int n1 = (y-x)/capacity;
        div_rem(y-x, capacity);
        assert true == (y-x == n1*capacity);
        int n = -n1;
        assert true == (x-y == n*capacity);
        assert true == (x == n*capacity + y);
        division_round_to_zero(x, capacity);
        div_rem(x, capacity);
        assert true == (x%capacity == x);
        assert true == (x == (n*capacity + y)%capacity);
        assert true == (x + capacity == (n*capacity + y)%capacity + capacity);
        mod_rotate(x, capacity);
        assert true == ((x+capacity)%capacity == x);
        assert true == (x == ((n*capacity + y)%capacity + capacity)%capacity);

        loop_injection_n(y, capacity, n);
        assert true == ((y - x) == (y - x)/capacity*capacity);
        assert true == (((y%capacity) + capacity)%capacity == x);
        assert(loop_fp(y, capacity) == x);
        return 0;
    } else {
        assert(z == ((y-x)%capacity + capacity)%capacity);
        assert(0 < z);
        assert(z < capacity);
        assert(0 <= (capacity - z + y));

        if (0 <= y-x) {
        div_rem(y-x, capacity);
        assert true == (0 <= (y-x)%capacity);
        mod_rotate((y-x)%capacity, capacity);
        mod_bijection((y-x)%capacity, capacity);
        assert true == ((y-x)%capacity == ((y-x)%capacity + capacity)%capacity);

        if (y-x < capacity) {
            mod_bijection((y-x), capacity);
            assert true == ((y-x)%capacity == y-x);

            mod_rotate(x, capacity);
            mod_bijection(x, capacity);
            assert true == (x == (capacity + x)%capacity);
            mod_rotate((capacity + x)%capacity, capacity);
            mod_bijection((capacity + x)%capacity, capacity);
            assert true == (x == (((capacity + x)%capacity + capacity)%capacity));
        } else {
            assert false;
        }

        } else {
        assert true == (y-x < 0);
        assert true == (-capacity < y-x);

        mod_bijection(y-x, capacity);
        assert true == ((y-x)%capacity == y-x);
        mod_bijection((y-x) + capacity, capacity);
        mod_bijection(x, capacity);
        mod_rotate(x, capacity);
        assert true == (x == ((x%capacity + capacity)%capacity));
        }
        assert true == (((capacity - z + y)%capacity + capacity)%capacity == x);
        return capacity - z;
    }

    }

    lemma void inc_modulo_loop_hlp(int a, int quotient, int capacity)
    requires 0 <= a &*& 0 < capacity &*&
            0 <= a - quotient * capacity &*&
            a - quotient * capacity < capacity;
    ensures loop_fp(loop_fp(a, capacity) + 1, capacity) ==
            loop_fp(a + 1, capacity);
    {
    int b = a - quotient * capacity;
    loop_injection_n(b, capacity, quotient);
    loop_bijection(b, capacity);
    if (b + 1 < capacity) {
        loop_injection_n(b + 1, capacity, quotient);
    } else {
        assert capacity <= b + 1;
        loop_injection_n(b + 1, capacity, quotient);
        loop_injection(0, capacity);
        loop_bijection(0, capacity);

    }
    }

    lemma void inc_modulo_loop(int a, int capacity)
    requires 0 <= a &*& 0 < capacity;
    ensures loop_fp(loop_fp(a, capacity) + 1, capacity) ==
            loop_fp(a + 1, capacity);
    {
    int quotient = a / capacity;
    div_rem(a, capacity);
    inc_modulo_loop_hlp(a, a/capacity, capacity);
    }//took 30m

    lemma void div_exact(int a, int b)
        requires    0 <= a &*& 0 < b;
        ensures     a*b/b == a;
    {
        div_rem_nonneg(0, b);
        div_incr(0, b);
        if (a != 0) {
            for (int i = 1; i < a; i++)
                invariant 1 <= i &*& i <= a &*& i*b/b == i;
                decreases a - i;
            {
                mul_nonzero(i, b);
                div_incr(i * b, b);
            }
        }
    }

    lemma void div_exact_rev(int a, int b)
        requires    0 <= a &*& 0 < b;
        ensures     a/b*b <= a;
    {
        div_rem_nonneg(a, b);
    }

    lemma void div_lt(int a, int b, int c)
        requires    0 <= a &*& 0 < b &*& 0 < c &*& a < b*c;
        ensures     a/c < b*c/c;
    {
        div_exact(b, c);
        div_rem_nonneg(a, c);
        if (a/c >= b) {
            mul_mono(b, a/c, c);
        }
    }

    lemma void div_ge(int a, int b, int c)
        requires    0 <= a &*& 0 < c &*& a <= b;
        ensures     a/c <= b/c;
    {
        if (a < b) {
            div_rem_nonneg(a, c);
            div_rem_nonneg(b, c);
            div_exact(a/c, c);
            div_exact(b/c, c);
            assert ((a/c)*c < (b/c)*c || a%c < b%c);
            if ((a/c)*c > (b/c)*c) {
                mul_nonnegative(b/c, c);
                div_lt((b/c)*c, a/c, c);
                mul_mono_l((b/c) + 1, a/c, c);
                assert false;
            }
            if ((a/c)*c < (b/c)*c) {
                mul_nonnegative(a/c, c);
                div_lt((a/c)*c, b/c, c);
            }
        }
    }

    lemma void loop_fp_pop(int k, int capacity)
        requires    0 <= k &*& 0 < capacity;
        ensures     loop_fp(k, capacity) == k % capacity;
    {
        div_mod_gt_0(k%capacity, k, capacity);
        mod_rotate(k%capacity, capacity);
        mod_bijection(k%capacity, capacity);
    }

    lemma void mod_reduce(int a, int b, int k)
        requires    0 <= a &*& 0 < b &*& 0 <= k;
        ensures     (a + b*k) % b == a % b;
    {
        mul_nonnegative(b, k);
        loop_injection_n(a, b, k);
        loop_fp_pop(a + b*k, b);
        loop_fp_pop(a, b);
    }
    
    lemma void mod_mod(int a, int b, int mod)
    requires a >= 0 &*& b >= 0 &*& mod > 0;
    ensures ((a % mod) + b) % mod == (a + b) % mod;
    {
    int arem = a % mod;
    int adiv = a / mod;
    int brem = b % mod;
    int bdiv = b / mod;
    div_rem_nonneg(a, mod);
    div_rem_nonneg(b, mod);
    mod_reduce(arem+brem, mod, adiv+bdiv);
    mod_reduce(arem+b, mod, adiv);
    }

    lemma void div_minus_one(int a, int b)
        requires    0 < a &*& 0 < b;
        ensures     (a*b - 1) / b == a - 1;
    {
        div_exact(a, b);
        div_exact(a - 1, b);
        mul_nonzero(a, b);
        div_lt(a*b - 1, a, b);
        mul_nonnegative(a-1, b);
        div_ge((a-1)*b, a*b - 1, b);
    }

    lemma void div_plus_one(int a, int b)
        requires    0 < a &*& 1 < b;
        ensures     (a*b + 1) / b == a;
    {
        div_exact(a, b);
        div_exact(a + 1, b);
        mul_nonnegative(a, b);
        div_lt(a*b+1, a+1, b);
        div_ge(a*b, a*b + 1, b);
    }

    lemma void mod_rotate_mul(int a, int b)
        requires    0 <= a &*& 0 < b;
        ensures     ((a * b) % b) == 0;
    {
        div_exact(a, b);
        mul_nonnegative(a, b);
        div_rem_nonneg(a * b, b);
    }

lemma void mod_compensate(int a, int m)
requires a >= 0 &*& m > 0;
ensures (a + (m - (a % m))) % m == 0;
{
	int r = a % m;
	if (r == 0) {
		mod_rotate(a, m);
	} else {
		div_rem_nonneg(a, m);
		assert a == (a / m) * m + a % m;
		assert a == (a / m) * m + r;
		assert a + (m - (a % m)) == a + m - r;
		assert a + m - r == (a / m) * m + r + m - r;
		assert a + m - r == (a / m) * m + m;
		assert (a + m - r) % m == ((a / m) * m + m) % m;
		mul_mono(0, a / m, m);
		mod_rotate((a / m) * m, m);
		assert (a + m - r) % m == ((a / m) * m) % m;
		mod_rotate_mul(a/m, m);
	}
}

@*/
