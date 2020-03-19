/**********************************************************************

  util.c -

  $Author$
  created at: Fri Mar 10 17:22:34 JST 1995

  Copyright (C) 1993-2008 Yukihiro Matsumoto

**********************************************************************/

#if defined __MINGW32__ || defined __MINGW64__
# define MINGW_HAS_SECURE_API 1
#endif

#include "ruby/config.h"

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdio.h>

#ifdef _WIN32
# include "missing/file.h"
#endif

#include "internal.h"
#include "internal/sanitizers.h"
#include "internal/util.h"
#include "ruby/util.h"

const char ruby_hexdigits[] = "0123456789abcdef0123456789ABCDEF";
#define hexdigit ruby_hexdigits

unsigned long
ruby_scan_oct(const char *start, size_t len, size_t *retlen)
{
    register const char *s = start;
    register unsigned long retval = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        if ((s[0] < '0') || ('7' < s[0])) {
            break;
        }
	retval <<= 3;
	retval |= *s++ - '0';
    }
    *retlen = (int)(s - start);	/* less than len */
    return retval;
}

unsigned long
ruby_scan_hex(const char *start, size_t len, size_t *retlen)
{
    register const char *s = start;
    register unsigned long retval = 0;
    const char *tmp;
    size_t i = 0;

    for (i = 0; i < len; i++) {
        if (! s[0]) {
            break;
        }
        tmp = strchr(hexdigit, *s);
        if (! tmp) {
            break;
        }
	retval <<= 4;
	retval |= (tmp - hexdigit) & 15;
	s++;
    }
    *retlen = (int)(s - start);	/* less than len */
    return retval;
}

const signed char ruby_digit36_to_number_table[] = {
    /*     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f */
    /*0*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*1*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*2*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*3*/  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    /*4*/ -1,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
    /*5*/ 25,26,27,28,29,30,31,32,33,34,35,-1,-1,-1,-1,-1,
    /*6*/ -1,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
    /*7*/ 25,26,27,28,29,30,31,32,33,34,35,-1,-1,-1,-1,-1,
    /*8*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*9*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*a*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*b*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*c*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*d*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*e*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /*f*/ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

NO_SANITIZE("unsigned-integer-overflow", extern unsigned long ruby_scan_digits(const char *str, ssize_t len, int base, size_t *retlen, int *overflow));
unsigned long
ruby_scan_digits(const char *str, ssize_t len, int base, size_t *retlen, int *overflow)
{

    const char *start = str;
    unsigned long ret = 0, x;
    unsigned long mul_overflow = (~(unsigned long)0) / base;

    *overflow = 0;

    if (!len) {
	*retlen = 0;
	return 0;
    }

    do {
	int d = ruby_digit36_to_number_table[(unsigned char)*str++];
        if (d == -1 || base <= d) {
	    --str;
	    break;
        }
        if (mul_overflow < ret)
            *overflow = 1;
        ret *= base;
        x = ret;
        ret += d;
        if (ret < x)
            *overflow = 1;
    } while (len < 0 || --len);
    *retlen = str - start;
    return ret;
}

unsigned long
ruby_strtoul(const char *str, char **endptr, int base)
{
    int c, b, overflow;
    int sign = 0;
    size_t len;
    unsigned long ret;
    const char *subject_found = str;

    if (base == 1 || 36 < base) {
        errno = EINVAL;
        return 0;
    }

    while ((c = *str) && ISSPACE(c))
        str++;

    if (c == '+') {
        sign = 1;
        str++;
    }
    else if (c == '-') {
        sign = -1;
        str++;
    }

    if (str[0] == '0') {
        subject_found = str+1;
        if (base == 0 || base == 16) {
            if (str[1] == 'x' || str[1] == 'X') {
                b = 16;
                str += 2;
            }
            else {
                b = base == 0 ? 8 : 16;
                str++;
            }
        }
        else {
            b = base;
            str++;
        }
    }
    else {
        b = base == 0 ? 10 : base;
    }

    ret = ruby_scan_digits(str, -1, b, &len, &overflow);

    if (0 < len)
        subject_found = str+len;

    if (endptr)
        *endptr = (char*)subject_found;

    if (overflow) {
        errno = ERANGE;
        return ULONG_MAX;
    }

    if (sign < 0) {
        ret = (unsigned long)(-(long)ret);
        return ret;
    }
    else {
        return ret;
    }
}

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif

#ifndef S_ISDIR
#   define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

typedef int (cmpfunc_t)(const void*, const void*, void*);

#if defined HAVE_QSORT_S && defined RUBY_MSVCRT_VERSION
/* In contrast to its name, Visual Studio qsort_s is incompatible with
 * C11 in the order of the comparison function's arguments, and same
 * as BSD qsort_r rather. */
# define qsort_r(base, nel, size, arg, cmp) qsort_s(base, nel, size, cmp, arg)
# define cmp_bsd_qsort cmp_ms_qsort
# define HAVE_BSD_QSORT_R 1
#endif

#if defined HAVE_BSD_QSORT_R
struct bsd_qsort_r_args {
    cmpfunc_t *cmp;
    void *arg;
};

static int
cmp_bsd_qsort(void *d, const void *a, const void *b)
{
    const struct bsd_qsort_r_args *args = d;
    return (*args->cmp)(a, b, args->arg);
}

void
ruby_qsort(void* base, const size_t nel, const size_t size, cmpfunc_t *cmp, void *d)
{
    struct bsd_qsort_r_args args;
    args.cmp = cmp;
    args.arg = d;
    qsort_r(base, nel, size, &args, cmp_bsd_qsort);
}
#elif defined HAVE_QSORT_S
/* C11 qsort_s has the same arguments as GNU's, but uses
 * runtime-constraints handler. */
void
ruby_qsort(void* base, const size_t nel, const size_t size, cmpfunc_t *cmp, void *d)
{
    if (!nel || !size) return;  /* nothing to sort */

    /* get rid of runtime-constraints handler for MT-safeness */
    if (!base || !cmp) return;
    if (nel > RSIZE_MAX || size > RSIZE_MAX) return;

    qsort_s(base, nel, size, cmp, d);
}
# define HAVE_GNU_QSORT_R 1
#elif !defined HAVE_GNU_QSORT_R
/* mm.c */

#define mmtype long
#define mmcount (16 / SIZEOF_LONG)
#define A ((mmtype*)a)
#define B ((mmtype*)b)
#define C ((mmtype*)c)
#define D ((mmtype*)d)

#define mmstep (sizeof(mmtype) * mmcount)
#define mmprepare(base, size) do {\
 if (((VALUE)(base) % sizeof(mmtype)) == 0 && ((size) % sizeof(mmtype)) == 0) \
   if ((size) >= mmstep) mmkind = 1;\
   else              mmkind = 0;\
 else                mmkind = -1;\
 high = ((size) / mmstep) * mmstep;\
 low  = ((size) % mmstep);\
} while (0)\

#define mmarg mmkind, size, high, low
#define mmargdecl int mmkind, size_t size, size_t high, size_t low

static void mmswap_(register char *a, register char *b, mmargdecl)
{
 if (a == b) return;
 if (mmkind >= 0) {
   register mmtype s;
#if mmcount > 1
   if (mmkind > 0) {
     register char *t = a + high;
     do {
       s = A[0]; A[0] = B[0]; B[0] = s;
       s = A[1]; A[1] = B[1]; B[1] = s;
#if mmcount > 2
       s = A[2]; A[2] = B[2]; B[2] = s;
#if mmcount > 3
       s = A[3]; A[3] = B[3]; B[3] = s;
#endif
#endif
       a += mmstep; b += mmstep;
     } while (a < t);
   }
#endif
   if (low != 0) { s = A[0]; A[0] = B[0]; B[0] = s;
#if mmcount > 2
     if (low >= 2 * sizeof(mmtype)) { s = A[1]; A[1] = B[1]; B[1] = s;
#if mmcount > 3
       if (low >= 3 * sizeof(mmtype)) {s = A[2]; A[2] = B[2]; B[2] = s;}
#endif
     }
#endif
   }
 }
 else {
   register char *t = a + size, s;
   do {s = *a; *a++ = *b; *b++ = s;} while (a < t);
 }
}
#define mmswap(a,b) mmswap_((a),(b),mmarg)

/* a, b, c = b, c, a */
static void mmrot3_(register char *a, register char *b, register char *c, mmargdecl)
{
 if (mmkind >= 0) {
   register mmtype s;
#if mmcount > 1
   if (mmkind > 0) {
     register char *t = a + high;
     do {
       s = A[0]; A[0] = B[0]; B[0] = C[0]; C[0] = s;
       s = A[1]; A[1] = B[1]; B[1] = C[1]; C[1] = s;
#if mmcount > 2
       s = A[2]; A[2] = B[2]; B[2] = C[2]; C[2] = s;
#if mmcount > 3
       s = A[3]; A[3] = B[3]; B[3] = C[3]; C[3] = s;
#endif
#endif
       a += mmstep; b += mmstep; c += mmstep;
     } while (a < t);
   }
#endif
   if (low != 0) { s = A[0]; A[0] = B[0]; B[0] = C[0]; C[0] = s;
#if mmcount > 2
     if (low >= 2 * sizeof(mmtype)) { s = A[1]; A[1] = B[1]; B[1] = C[1]; C[1] = s;
#if mmcount > 3
       if (low == 3 * sizeof(mmtype)) {s = A[2]; A[2] = B[2]; B[2] = C[2]; C[2] = s;}
#endif
     }
#endif
   }
 }
 else {
   register char *t = a + size, s;
   do {s = *a; *a++ = *b; *b++ = *c; *c++ = s;} while (a < t);
 }
}
#define mmrot3(a,b,c) mmrot3_((a),(b),(c),mmarg)

/* qs6.c */
/*****************************************************/
/*                                                   */
/*          qs6   (Quick sort function)              */
/*                                                   */
/* by  Tomoyuki Kawamura              1995.4.21      */
/* kawamura@tokuyama.ac.jp                           */
/*****************************************************/

typedef struct { char *LL, *RR; } stack_node; /* Stack structure for L,l,R,r */
#define PUSH(ll,rr) do { top->LL = (ll); top->RR = (rr); ++top; } while (0)  /* Push L,l,R,r */
#define POP(ll,rr)  do { --top; (ll) = top->LL; (rr) = top->RR; } while (0)      /* Pop L,l,R,r */

#define med3(a,b,c) ((*cmp)((a),(b),d)<0 ?                                   \
                       ((*cmp)((b),(c),d)<0 ? (b) : ((*cmp)((a),(c),d)<0 ? (c) : (a))) : \
                       ((*cmp)((b),(c),d)>0 ? (b) : ((*cmp)((a),(c),d)<0 ? (a) : (c))))

void
ruby_qsort(void* base, const size_t nel, const size_t size, cmpfunc_t *cmp, void *d)
{
  register char *l, *r, *m;          	/* l,r:left,right group   m:median point */
  register int t, eq_l, eq_r;       	/* eq_l: all items in left group are equal to S */
  char *L = base;                    	/* left end of current region */
  char *R = (char*)base + size*(nel-1); /* right end of current region */
  size_t chklim = 63;                   /* threshold of ordering element check */
  enum {size_bits = sizeof(size) * CHAR_BIT};
  stack_node stack[size_bits];          /* enough for size_t size */
  stack_node *top = stack;
  int mmkind;
  size_t high, low, n;

  if (nel <= 1) return;        /* need not to sort */
  mmprepare(base, size);
  goto start;

  nxt:
  if (stack == top) return;    /* return if stack is empty */
  POP(L,R);

  for (;;) {
    start:
    if (L + size == R) {       /* 2 elements */
      if ((*cmp)(L,R,d) > 0) mmswap(L,R); goto nxt;
    }

    l = L; r = R;
    n = (r - l + size) / size;  /* number of elements */
    m = l + size * (n >> 1);    /* calculate median value */

    if (n >= 60) {
      register char *m1;
      register char *m3;
      if (n >= 200) {
	n = size*(n>>3); /* number of bytes in splitting 8 */
	{
	  register char *p1 = l  + n;
	  register char *p2 = p1 + n;
	  register char *p3 = p2 + n;
	  m1 = med3(p1, p2, p3);
	  p1 = m  + n;
	  p2 = p1 + n;
	  p3 = p2 + n;
	  m3 = med3(p1, p2, p3);
	}
      }
      else {
	n = size*(n>>2); /* number of bytes in splitting 4 */
	m1 = l + n;
	m3 = m + n;
      }
      m = med3(m1, m, m3);
    }

    if ((t = (*cmp)(l,m,d)) < 0) {                           /*3-5-?*/
      if ((t = (*cmp)(m,r,d)) < 0) {                         /*3-5-7*/
	if (chklim && nel >= chklim) {   /* check if already ascending order */
	  char *p;
	  chklim = 0;
	  for (p=l; p<r; p+=size) if ((*cmp)(p,p+size,d) > 0) goto fail;
	  goto nxt;
	}
	fail: goto loopA;                                    /*3-5-7*/
      }
      if (t > 0) {
	if ((*cmp)(l,r,d) <= 0) {mmswap(m,r); goto loopA;}     /*3-5-4*/
	mmrot3(r,m,l); goto loopA;                           /*3-5-2*/
      }
      goto loopB;                                            /*3-5-5*/
    }

    if (t > 0) {                                             /*7-5-?*/
      if ((t = (*cmp)(m,r,d)) > 0) {                         /*7-5-3*/
	if (chklim && nel >= chklim) {   /* check if already ascending order */
	  char *p;
	  chklim = 0;
	  for (p=l; p<r; p+=size) if ((*cmp)(p,p+size,d) < 0) goto fail2;
	  while (l<r) {mmswap(l,r); l+=size; r-=size;}  /* reverse region */
	  goto nxt;
	}
	fail2: mmswap(l,r); goto loopA;                      /*7-5-3*/
      }
      if (t < 0) {
	if ((*cmp)(l,r,d) <= 0) {mmswap(l,m); goto loopB;}   /*7-5-8*/
	mmrot3(l,m,r); goto loopA;                           /*7-5-6*/
      }
      mmswap(l,r); goto loopA;                               /*7-5-5*/
    }

    if ((t = (*cmp)(m,r,d)) < 0)  {goto loopA;}              /*5-5-7*/
    if (t > 0) {mmswap(l,r); goto loopB;}                    /*5-5-3*/

    /* determining splitting type in case 5-5-5 */           /*5-5-5*/
    for (;;) {
      if ((l += size) == r)      goto nxt;                   /*5-5-5*/
      if (l == m) continue;
      if ((t = (*cmp)(l,m,d)) > 0) {mmswap(l,r); l = L; goto loopA;}/*575-5*/
      if (t < 0)                 {mmswap(L,l); l = L; goto loopB;}  /*535-5*/
    }

    loopA: eq_l = 1; eq_r = 1;  /* splitting type A */ /* left <= median < right */
    for (;;) {
      for (;;) {
	if ((l += size) == r)
	  {l -= size; if (l != m) mmswap(m,l); l -= size; goto fin;}
	if (l == m) continue;
	if ((t = (*cmp)(l,m,d)) > 0) {eq_r = 0; break;}
	if (t < 0) eq_l = 0;
      }
      for (;;) {
	if (l == (r -= size))
	  {l -= size; if (l != m) mmswap(m,l); l -= size; goto fin;}
	if (r == m) {m = l; break;}
	if ((t = (*cmp)(r,m,d)) < 0) {eq_l = 0; break;}
	if (t == 0) break;
      }
      mmswap(l,r);    /* swap left and right */
    }

    loopB: eq_l = 1; eq_r = 1;  /* splitting type B */ /* left < median <= right */
    for (;;) {
      for (;;) {
	if (l == (r -= size))
	  {r += size; if (r != m) mmswap(r,m); r += size; goto fin;}
	if (r == m) continue;
	if ((t = (*cmp)(r,m,d)) < 0) {eq_l = 0; break;}
	if (t > 0) eq_r = 0;
      }
      for (;;) {
	if ((l += size) == r)
	  {r += size; if (r != m) mmswap(r,m); r += size; goto fin;}
	if (l == m) {m = r; break;}
	if ((t = (*cmp)(l,m,d)) > 0) {eq_r = 0; break;}
	if (t == 0) break;
      }
      mmswap(l,r);    /* swap left and right */
    }

    fin:
    if (eq_l == 0)                         /* need to sort left side */
      if (eq_r == 0)                       /* need to sort right side */
	if (l-L < R-r) {PUSH(r,R); R = l;} /* sort left side first */
	else           {PUSH(L,l); L = r;} /* sort right side first */
      else R = l;                          /* need to sort left side only */
    else if (eq_r == 0) L = r;             /* need to sort right side only */
    else goto nxt;                         /* need not to sort both sides */
  }
}
#endif /* HAVE_GNU_QSORT_R */

#ifdef HAVE_GNU_QSORT_R

// mm引用
#define mmtype long
#define mmcount (16 / SIZEOF_LONG)
#define A ((mmtype*)a)
#define B ((mmtype*)b)
#define C ((mmtype*)c)
#define D ((mmtype*)d)

#define mmstep (sizeof(mmtype) * mmcount)
#define mmprepare(base, size) do {\
 if (((VALUE)(base) % sizeof(mmtype)) == 0 && ((size) % sizeof(mmtype)) == 0) \
   if ((size) >= mmstep) mmkind = 1;\
   else              mmkind = 0;\
 else                mmkind = -1;\
 high = ((size) / mmstep) * mmstep;\
 low  = ((size) % mmstep);\
} while (0)\

#define mmarg mmkind, size, high, low
#define mmargdecl int mmkind, size_t size, size_t high, size_t low

static void mmswap_(register char *a, register char *b, mmargdecl)
{
 if (a == b) return;
 if (mmkind >= 0) {
   register mmtype s;
#if mmcount > 1
   if (mmkind > 0) {
     register char *t = a + high;
     do {
       s = A[0]; A[0] = B[0]; B[0] = s;
       s = A[1]; A[1] = B[1]; B[1] = s;
#if mmcount > 2
       s = A[2]; A[2] = B[2]; B[2] = s;
#if mmcount > 3
       s = A[3]; A[3] = B[3]; B[3] = s;
#endif
#endif
       a += mmstep; b += mmstep;
     } while (a < t);
   }
#endif
   if (low != 0) { s = A[0]; A[0] = B[0]; B[0] = s;
#if mmcount > 2
     if (low >= 2 * sizeof(mmtype)) { s = A[1]; A[1] = B[1]; B[1] = s;
#if mmcount > 3
       if (low >= 3 * sizeof(mmtype)) {s = A[2]; A[2] = B[2]; B[2] = s;}
#endif
     }
#endif
   }
 }
 else {
   register char *t = a + size, s;
   do {s = *a; *a++ = *b; *b++ = s;} while (a < t);
 }
}
#define mmswap(a,b) mmswap_((a),(b),mmarg)

#endif

// ここまで


#define TIMSORT_MINGALLOP 7
#define TIMSORT_STACKSIZE 128
#define MAX(a,b) ((a)>(b) ? (a) : (b))
#define MIN(a,b) ((a)<(b) ? (a) : (b))
typedef struct { char *pos;size_t len; } timsort_stack_node;
typedef struct { char *tmp_store; size_t allocated_size;} tim_temp_array;


// 最小ランの計算
int
rb_calc_minrun(const size_t nel) {
  const int shift = MAX(64 - nlz_long_long(nel), 6) - 6;
  const int minrun = (int)(nel >> shift);
  if (nel & ((1ull << shift) - 1)) {
    return minrun + 1;
  }
  return minrun;
}

size_t
rb_timsort_galloping(char* base, size_t len, char* key,size_t anchor, int isRight, cmpfunc_t *cmp, void *d, mmargdecl) {
  int last_o = 0, o, max_o, o_sign;
  size_t l, c, r;
  int cp = (*cmp)(key,base+anchor*size,d);

  if (cp < 0 || (!isRight && cp == 0)) {
    if (anchor == 0) {
      return 0;
    }
    o = -1; o_sign = -1; max_o = -(int)anchor;
  } else {
    if (anchor == len - 1) {
      return len;
    }
    o = 1; o_sign = 1; max_o = (int)(len - anchor - 1);
  }

  for (;;) {
    if (max_o / o <= 1) {
      o = max_o;
      if (o < 0) {
        cp = (*cmp)(key, base, d);
        if ((isRight && cp < 0) || (!isRight && cp <= 0)) {
          return 0;
        }
      } else {
        cp = (*cmp)(base + (len - 1) * size, key, d);
        if ((isRight && cp <= 0) || (!isRight && cp < 0)) {
          return len;
        }
      }
      break;
    }
    c = anchor+o;
    cp = (*cmp)(key, base + c * size, d);
    if (o > 0) {
      if ((isRight && cp < 0) || (!isRight && cp <= 0)) {
        break;
      }
    } else {
      if ((isRight && cp >= 0) || (!isRight && cp > 0)) {
        break;
      }
    }
    last_o = o;
    o = (o << 1) + o_sign;
  }

  if (o < 0) {
    l = anchor + o;
    r = anchor + last_o;
  } else {
    l = anchor + last_o;
    r = anchor + o;
  }
  while (r - l > 1) {
    c = l + ((r - l) >> 1);
    cp = (*cmp)(key, base + c * size, d);
    if ((isRight && cp < 0) || (!isRight && cp <= 0) ){
      r = c;
    } else {
      l = c;
    }

  }
  return r;
}


#define COPY_PLUS(L,R,pl,pr,size) do{memcpy(L+pl*size,R+pr*size,size);pl++;pr++;}while(0)
#define COPY_MINUS(L,R,pl,pr,size) do{memcpy(L+pl*size,R+pr*size,size);pl--;pr--;}while(0)

void
rb_timsort_left_merge(cmpfunc_t *cmp, void *d, char *L, char *R, int L_len, int R_len,char *storage, int *mingallop, mmargdecl) {
  int ming = *mingallop;
  int L_num, R_num, pl = 0, pr = 0, pb = 0;
  char* base = L;
  size_t k;
  memcpy(storage, base, L_len * size);
  L = storage;
  COPY_PLUS(base, R, pb, pr, size);

  if (R_len == 1) {
    //終了処理
    memcpy(base + pb * size, L + pl * size, size * (L_len - pl));
    *mingallop = ming;
    return;
  }

  for (;;) {
    L_num = R_num = 0;
    for (;;) {
      if ((*cmp)(L + pl * size, R + pr * size, d) <= 0) {
        COPY_PLUS(base, L, pb, pl, size);
        L_num++;  R_num = 0;
        if (ming <= L_num) break;
      } else {
        COPY_PLUS(base, R, pb, pr, size);
        R_num++;  L_num = 0;
        if (pr == R_len) {
          //終了処理
          memcpy(base + pb * size, L + pl * size, size * (L_len - pl));
          *mingallop = ming;
          return;
        }
        if (ming <= R_num) break;
      }
    }
    ming++;
    for (;;) {
      if (ming != 0) ming--;
      k = rb_timsort_galloping(L + pl * size, L_len - pl, R + pr * size, 0, 1, cmp, d, mmarg);
      memcpy(base + pb * size, L + pl * size, k * size); pb += k; pl += k;
      COPY_PLUS(base, R, pb, pr, size);
      if (pr == R_len) {
        //終了処理
        memcpy(base + pb * size, L + pl * size, size * (L_len - pl));
        *mingallop = ming;
        return;
      }
      if (L_num && k < TIMSORT_MINGALLOP) {
        ming++;
        break;
      }
      k = rb_timsort_galloping(R + pr * size, R_len - pr, L + pl * size, 0, 0, cmp, d, mmarg);
      memmove(base + pb * size, R + pr * size, k * size); pb += k; pr += k;
      if (pr == R_len) {
        //終了処理
        memcpy(base + pb * size, L + pl * size, size * (L_len - pl));
        *mingallop = ming;
        return;
      }
      COPY_PLUS(base, L, pb, pl, size);
      if (R_num && k < TIMSORT_MINGALLOP) {
        ming++;
        break;
      }
    }
  }

}

void
rb_timsort_right_merge(cmpfunc_t *cmp, void *d, char *L, char *R, int L_len, int R_len,char *storage, int *mingallop, mmargdecl) {
  int ming = *mingallop;
  int L_num, R_num, pl = L_len - 1, pr = R_len - 1, pb = L_len + R_len - 1;
  char* base = L;
  size_t k;

  memcpy(storage, R, R_len * size);
  R = storage;
  COPY_MINUS(base, L, pb, pl, size);


  if (L_len == 1) {
    //終了処理
    memcpy(base, R, size * (pr + 1));
    *mingallop = ming;
    return;
  }

  for (;;) {
    L_num = R_num = 0;
    for (;;) {
      if ((*cmp)(L + pl * size, R + pr * size, d) <= 0) {
        COPY_MINUS(base, R, pb, pr, size);
        R_num++; L_num = 0;
        if (ming <= R_num) break;
      } else {
        COPY_MINUS(base, L, pb, pl, size);
        L_num++; R_num = 0;
        if (pl == -1) {

          //終了処理
          memcpy(base, R, size * (pr + 1));
          *mingallop = ming;
          return;
        }
        if (ming <= L_num) break;
      }
    }
    ming++;
    for (;;) {
      if (ming != 0) ming--;
      k = rb_timsort_galloping(L, pl + 1, R + pr * size, pl, 1, cmp, d, mmarg);
      memmove(base + (pr + k + 1) * size, L + k * size, (pl + 1 - k) * size);
      pb = pr + (int)k; pl = (int)(k - 1);

      if (pl == -1) {
        //終了処理
        memcpy(base, R, size * (pr + 1));
        *mingallop = ming;
        return;
      }
      COPY_MINUS(base, R, pb, pr, size);
      if (L_num && pl + 1 - k < TIMSORT_MINGALLOP) {
        ming++;
        break;
      }
      k = rb_timsort_galloping(R, pr + 1, L + pl * size, pr, 0, cmp, d, mmarg);
      memcpy(base + (pl + k + 1) * size, R + k * size, (pr + 1 - k) * size); pb = pl + (int)k; pr = (int)(k - 1);
      COPY_MINUS(base, L, pb, pl, size);
      if (pl == -1) {
        //終了処理
        memcpy(base, R, size * (pr + 1));
        *mingallop = ming;
        return;
      }
      
      if (R_num && pr + 1 - k < TIMSORT_MINGALLOP) {
        ming++;
        break;
      }
    }
  }

}

void
rb_timsort_merge(void* base, const size_t nel, cmpfunc_t *cmp, void *d, timsort_stack_node *stack,
    timsort_stack_node *cur_stack, int *mingallop, tim_temp_array *arr, mmargdecl) {
  size_t L_len = (cur_stack - 2) -> len;
  size_t R_len = (cur_stack - 1) -> len;
  char *L = (cur_stack - 2) -> pos;
  char *R = (cur_stack - 1) -> pos;
  size_t arr_size;

  size_t k = rb_timsort_galloping(L, L_len, R, 0, 1, cmp, d, mmarg);
  L += size * k;
  L_len -= k;
  if (L_len == 0) { // ギャロッピングで全データがRの先頭より小さいとき
    *mingallop /= 2;
    return;
  }
  k = rb_timsort_galloping(R, R_len, R-size, R_len-1, 0, cmp, d, mmarg);
  R_len = k;

  //  メモリ確保
  arr_size = MIN(L_len, R_len);
  if (arr -> tmp_store == NULL || arr -> allocated_size < arr_size) {
    arr -> tmp_store = xrealloc(arr -> tmp_store, arr_size * size);
    arr -> allocated_size = arr_size;
  }

  if (L_len < R_len) {
    rb_timsort_left_merge(cmp, d, L, R, L_len, R_len, arr -> tmp_store, mingallop, mmarg);
  } else {
    rb_timsort_right_merge(cmp, d, L, R, L_len, R_len, arr -> tmp_store, mingallop, mmarg);
  }

  return;

}



// cmp(x,y,d)の形で使うと比較できる
void
rb_timsort(void* base, const size_t nel, const size_t size, cmpfunc_t *cmp, void *d) {
  char *cur = base;  // いまソートしている場所
  const char *end = (char*)base + size * (nel - 1); // 右端
  int mingallop = TIMSORT_MINGALLOP;
  int min_run, run, trun;  // minrun -> データ数依存 run -> 最長列 trun -> 最低限run
  enum {size_bits = sizeof(size) * CHAR_BIT};
  timsort_stack_node stack[size_bits];          /* enough for size_t size */
  timsort_stack_node *top = stack;
  tim_temp_array _arr, *arr; 
  char *tmp = xmalloc(size);

  // mm用変数
  int mmkind;
  size_t high, low, n;

  // 不変条件をチェックし始める回数
  int check_inv_amount = 3;




  if (nel <= 1) return;
  mmprepare(base, size);
  if (nel < 64) {
    // 二分挿入ソート
    size_t i;
    size_t l, c, r;
    for (i = 1; i < nel; i++) {
      size_t j;
      size_t loc;
      if ((*cmp)(cur + (i - 1) * size, cur + i * size, d) <= 0) continue;
      memcpy(tmp, cur + i * size, size);
      l = 0; r = i - 1; c = r >> 1;
      if ((*cmp)(tmp, cur, d) < 0) {
        loc = 0;
      } else if ((*cmp)(tmp, cur + r * size, d) > 0) {
        loc = r;
      } else {
        while (1) {
          int v = (*cmp)(tmp, cur + c * size, d);
          if (v < 0) {
            if (c - l <= 1) {
              loc = c; break;
            }
            r = c;
          } else {
            if (r - c <= 1) {
              loc = c + 1;
              break;
            }
            l = c;
          }
          c = l + ((r - l) >> 1);
        }
      }
      
      memmove(cur + (loc + 1) * size, cur + loc * size, (i - loc) * size);
      memcpy(cur + loc * size, tmp, size);
    }
    return;
  }
  min_run = rb_calc_minrun(nel);

  arr = &_arr;
  arr -> allocated_size = 0;
  arr -> tmp_store = NULL;




  // スタックにノードをプッシュする部分
  for (;;) {

    // ランの計算

    if (end - cur == 0) {  // 現在地点が終点
      run = 1;
    } else if (end - cur == size) {  // 現在地点が終点1つ前
      if ((*cmp)(end - size, end, d) > 0) {  // 二要素の入れ替え
        mmswap(end - size, end);
      }
      run = 2;
    } else {
      char *pos = cur + 2 * size;
      if ((*cmp)(cur, cur + size, d) <= 0) { // 最初の2要素が昇順
        for (;;) {
          if (end - pos == 0) {
            break;
          }
          if ((*cmp)(pos - size, pos, d) > 0) {
            break;
          }
          pos += size;
        }
        run = (pos - cur) / size;
      } else {  // 降順
        for (;;) {
          if (end - pos == 0) {
            break;
          }
          if ((*cmp)(pos - size, pos, d) <= 0) {
            break;
          }
          pos += size;
        }
        run = (pos - cur) / size;
        { // 反転
          char *l = cur;
          pos -= size;
          while (l < pos) {
            mmswap(l, pos); l += size; pos -= size;
          }
        }
      }
    }


    trun = min_run;
    if (trun >= (end - cur) / size) { // 配列の端を超えたとき
      trun = (end - cur) / size + 1;
    }
    if (trun > run) { // ランが最小ランより短いとき
      // 二分挿入ソート
      size_t i;
      size_t l, c, r;
      for (i = run; i < trun; i++) {
        size_t j;
        size_t loc;
        if ((*cmp)(cur + (i - 1) * size, cur + i * size, d) <= 0) continue;
        memcpy(tmp, cur + i * size, size);
        l = 0; r = i - 1; c = r >> 1;
        if ((*cmp)(tmp, cur, d) < 0) {
          loc = 0;
        } else if ((*cmp)(tmp, cur + r * size, d) > 0) {
          loc = r;
        } else {
          
          while (1) {
            int v = (*cmp)(tmp, cur + c * size, d);
            if (v < 0) {
              if (c - l <= 1) {
                loc = c; break;
              }
              r = c;
            } else {
              if (r - c <= 1) {
                loc = c + 1;
                break;
              }
              l = c;
            }
            c = l + ((r - l) >> 1);
            
          }
        }
        memmove(cur + (loc + 1) * size, cur + loc * size, (i - loc) * size);
        memcpy(cur + loc * size, tmp, size);

      }
      run = trun;
    }

    //スタックへのプッシュ
    //一番上を参照するときは(top-1)->len と使う
    top -> pos = cur;
    top -> len = run;
    top++;

    cur += run * size;
    if (cur > end) {
      break; // 終了処理
    }

    // check_inv_amountの回数ぶん繰り返す
    if (check_inv_amount) {
      check_inv_amount--;
      continue;      
    }


    // 不変条件チェック部分

    for (;;) {
      //  breakするとpushの先頭に行く

      if (stack >= top - 1) { // スタック0 or 1
        break;
      }
      if (stack == top - 2) { // スタック2
        if ((top - 2) -> len > (top - 1) -> len) {  // 一番下の長さ > 一個上の長さ
          break;
        }
      } else {  // 要素数3以上
        if ((top - 3) -> len > (top - 2) -> len + (top - 1) -> len && (top - 2) -> len > (top - 1) -> len) {
          // top-3 > top-2 + top->1  &&  top-2 > top->1 を満たす場合はマージしない
          break;
        }
      }

      // ここを通る場合は不変条件を満たしていない
      // breakするとforを一つ抜け、不変条件チェックに進む
      for (;;) {

        if (stack >= top - 1) {  // スタック 0 or 1
          break;
        }
        if (stack == top - 2) { // スタック 2
          if ((top - 1) -> len + (top - 2) -> len == nel || (top - 1) -> len >= (top - 2) -> len) {
            //データ数とスタックの合計値が同じ or 不変条件
            rb_timsort_merge(base, nel, cmp, d, stack, top, &mingallop, arr, mmarg);
            (top - 2) -> len += (top - 1) -> len; top--; // POP
          }
          break;
        }

        if ((top - 2) -> len <= (top - 1) -> len) { //不変条件
          rb_timsort_merge(base, nel, cmp, d, stack, top, &mingallop, arr, mmarg);
          (top - 2) -> len += (top - 1) -> len; top--; // POP

        } else if (((top - 3) -> len <= (top - 2) -> len + (top - 1) -> len) ||
           ((stack <= top - 4) ? ((top - 4) -> len <= (top - 3) -> len + (top - 2) -> len) : (0))) {
          // 3要素の不変条件
          // スタックの要素が4以上のときは、深さ4つまで不変条件を確かめる

          rb_timsort_merge(base, nel, cmp, d, stack, top - 1, &mingallop, arr, mmarg);
          (top - 3) -> len += (top - 2) -> len;
          *(top - 2) = *(top - 1);  // 一番上をひとつ下ろしてくる
          top--;
          
        }
        break;

      }




    }

  }
  while (stack != top - 1) {
    rb_timsort_merge(base, nel, cmp, d, stack, top, &mingallop, arr, mmarg);
    
    (top - 2) -> len += (top - 1) -> len; top--; // POP
  }

  return;
}

char *
ruby_strdup(const char *str)
{
    char *tmp;
    size_t len = strlen(str) + 1;

    tmp = xmalloc(len);
    memcpy(tmp, str, len);

    return tmp;
}

char *
ruby_getcwd(void)
{
#if defined HAVE_GETCWD
# undef RUBY_UNTYPED_DATA_WARNING
# define RUBY_UNTYPED_DATA_WARNING 0
# if defined NO_GETCWD_MALLOC
    VALUE guard = Data_Wrap_Struct((VALUE)0, NULL, RUBY_DEFAULT_FREE, NULL);
    int size = 200;
    char *buf = xmalloc(size);

    while (!getcwd(buf, size)) {
	int e = errno;
	if (e != ERANGE) {
	    xfree(buf);
	    DATA_PTR(guard) = NULL;
	    rb_syserr_fail(e, "getcwd");
	}
	size *= 2;
	DATA_PTR(guard) = buf;
	buf = xrealloc(buf, size);
    }
# else
    VALUE guard = Data_Wrap_Struct((VALUE)0, NULL, free, NULL);
    char *buf, *cwd = getcwd(NULL, 0);
    DATA_PTR(guard) = cwd;
    if (!cwd) rb_sys_fail("getcwd");
    buf = ruby_strdup(cwd);	/* allocate by xmalloc */
    free(cwd);
# endif
    DATA_PTR(RB_GC_GUARD(guard)) = NULL;
#else
# ifndef PATH_MAX
#  define PATH_MAX 8192
# endif
    char *buf = xmalloc(PATH_MAX+1);

    if (!getwd(buf)) {
	int e = errno;
	xfree(buf);
	rb_syserr_fail(e, "getwd");
    }
#endif
    return buf;
}

void
ruby_each_words(const char *str, void (*func)(const char*, int, void*), void *arg)
{
    const char *end;
    int len;

    if (!str) return;
    for (; *str; str = end) {
	while (ISSPACE(*str) || *str == ',') str++;
	if (!*str) break;
	end = str;
	while (*end && !ISSPACE(*end) && *end != ',') end++;
	len = (int)(end - str);	/* assume no string exceeds INT_MAX */
	(*func)(str, len, arg);
    }
}

#undef strtod
#define strtod ruby_strtod
#undef dtoa
#define dtoa ruby_dtoa
#undef hdtoa
#define hdtoa ruby_hdtoa
#include "missing/dtoa.c"
