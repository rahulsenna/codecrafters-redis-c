#pragma once
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>

#define SSO_MAX 22

typedef enum { STR_KIND_SSO = 0, STR_KIND_HEAP, STR_KIND_VIEW } StrKind;
#define FLAG_HEAP 0x8000000000000000ULL  // bit 63
#define FLAG_VIEW 0x4000000000000000ULL  // bit 62

typedef struct String
{
  union
  {
    struct
    {
      char* ptr;
      size_t  len;
      size_t  cap;        // high bit = is_heap flag
    } heap;

    struct
    {
      char    buf[23];
      uint8_t len;        // high bit = 0, second bit = 0
    } sso;

    struct
    {
      char* ptr;
      size_t      len;
      size_t      flags;  // high bit = 0, second bit = is_view flag
    } view;
  };
} String;


static inline String _str_view(const char* cstr, size_t n)
{
  String out = { 0 };
  out.view.ptr = (char*) cstr;
  out.view.len = n;
  out.view.flags = FLAG_VIEW;
  return out;
}

static inline String _str_cpy(const char* cstr, size_t n)
{
  String out = { 0 };
  memset(&out, 0, sizeof(out));
  if (n <= SSO_MAX)
  {
    memcpy(out.sso.buf, cstr, n);
    out.sso.buf[n] = '\0';
    out.sso.len = (uint8_t) n;
    return out;
  }
  char* ptr = (char*) malloc(n + 1);
  memcpy(ptr, cstr, n);
  ptr[n] = '\0';
  out.heap.ptr = ptr;
  out.heap.len = n;
  out.heap.cap = n | FLAG_HEAP;
  return out;
}

/* init *String* from length, fill in data later */
static inline String str_init_len(size_t n)
{
  String out = { 0 };
  memset(&out, 0, sizeof(out));

  if (n <= SSO_MAX)
  {
    out.sso.buf[n] = '\0';
    out.sso.len = (uint8_t) n;
    return out;
  }

  char* ptr = (char*) malloc(n + 1);
  ptr[n] = '\0';
  out.heap.ptr = ptr;
  out.heap.len = n;
  out.heap.cap = n | FLAG_HEAP;
  return out;
}

static inline StrKind str_kind(const String* s)
{
  if (s->heap.cap & FLAG_HEAP) return STR_KIND_HEAP;
  if (s->view.flags & FLAG_VIEW) return STR_KIND_VIEW;
  return STR_KIND_SSO;
}

#define STR_IS_SSO(s)   (!((s).heap.cap & (FLAG_HEAP | FLAG_VIEW)))
#define PSTR_IS_SSO(s)   (!((s)->heap.cap & (FLAG_HEAP | FLAG_VIEW)))
#define STR_IS_VIEW(s)  ((s).view.flags & FLAG_VIEW)
#define PSTR_IS_VIEW(s)  ((s)->view.flags & FLAG_VIEW)
#define STR_IS_HEAP(s)  ((s).heap.cap & FLAG_HEAP)
#define PSTR_IS_HEAP(s)  ((s)->heap.cap & FLAG_HEAP)

static inline char* str_data(String* s)
{
  return PSTR_IS_SSO(s) ? s->sso.buf : s->view.ptr;
}
static inline size_t str_len(const String* s)
{
    return PSTR_IS_SSO(s) ? s->sso.len : s->view.len;
}
static inline size_t str_cap(const String* s)
{
  assert(STR_IS_HEAP(*s));
  return s->heap.cap & ~(FLAG_HEAP | FLAG_VIEW);
}

#define PSTR(s) (str_data(&s))
#define LSTR(s) (str_len(&s))

#define STR_FREE(s)                     \
do {                                    \
    if (STR_IS_HEAP(s))                 \
        free((s).heap.ptr);             \
    memset(&(s), 0, sizeof(s));         \
} while (0)

static inline String str_clone(String s)
{
  return _str_cpy(str_data(&s), str_len(&s));
}

#ifndef __cplusplus
static inline String _str_from_cstr(const char* s)
{
  return _str_cpy(s, strlen(s));
}

static inline String _str_view_from_cstr(const char* s)
{
  return _str_view(s, strlen(s));
}
static inline String _str_from_string(String s)
{
  return s;
}
static inline String _str_from_cstr_mut(char* s)
{
  return _str_from_cstr((const char*) s);
}

static inline String _str_view_from_cstr_mut(char* s)
{
  return _str_view_from_cstr(s);
}

#define str(x)                        \
    _Generic((0, (x)),                \
        String: _str_from_string,     \
        char *: _str_from_cstr_mut,   \
        const char *: _str_from_cstr  \
    )(x)

#define str_view(x)                        \
    _Generic((0, (x)),                     \
        String: _str_from_string,          \
        char *: _str_view_from_cstr_mut,   \
        const char *: _str_view_from_cstr  \
    )(x)
#else
static inline String str(String s)
{
  return s;
}
static inline String str(char* s)
{
  return _str_cpy(s, strlen(s));
}
static inline String str(const char* s)
{
  return _str_cpy(s, strlen(s));
}

static inline String str_view(String s) { return s; }
static inline String str_view(const char* s)
{
  return _str_view(s, strlen(s));
}
static inline String str_view(char* s)
{
  return _str_view(s, strlen(s));
}
#endif

static inline int str_eq(String a, String b)
{
  size_t la = str_len(&a), lb = str_len(&b);
  if (la != lb) return 0;
  const char* pa = str_data(&a);
  const char* pb = str_data(&b);
  return *pa == *pb && memcmp(pa, pb, la) == 0;
}
static inline int c_str_eq(String a, const char* b)
{
  return str_len(&a) == strlen(b) && *str_data(&a) == *b && memcmp(str_data(&a), b, str_len(&a)) == 0;
}

static inline int _str_reserve(String* s, size_t need)
{
  if (need <= SSO_MAX + 1 && !PSTR_IS_HEAP(s))
    return 1;

  if (PSTR_IS_HEAP(s))
  {
    if (str_cap(s) >= need)
      return 1;

    char* p = (char*) realloc(s->heap.ptr, need);
    if (!p)
      return 0;

    s->heap.ptr = p;
    s->heap.cap = need | FLAG_HEAP;
    return 1;
  }

  char* p = (char*) malloc(need);
  if (!p)
    return 0;

  memcpy(p, str_data(s), str_len(s));
  p[str_len(s)] = '\0';
  size_t sso_len = s->sso.len;
  s->heap.ptr = p;
  s->heap.len = sso_len;
  s->heap.cap = need | FLAG_HEAP;
  return 1;
}

static inline int str_cat(String* dst, String *src)
{
  size_t old_len = str_len(dst);
  size_t src_len = str_len(src);
  size_t new_len = old_len + src_len;

  if (new_len <= SSO_MAX)
  {
    char* src_data = str_data(src);
    if (PSTR_IS_VIEW(dst))
    {
      const char* view_ptr = dst->view.ptr;
      memmove(dst->sso.buf, view_ptr, dst->view.len);
      
    }
    memmove(dst->sso.buf + old_len, src_data, src_len);
    dst->sso.buf[new_len] = '\0';
    dst->sso.len = new_len;
    return 1;
  }

  ptrdiff_t alias_offset = 0;
  int aliased = PSTR_IS_HEAP(dst) && str_data(src) >= dst->heap.ptr && str_data(src) < dst->heap.ptr + dst->heap.len;
  if (aliased)
    alias_offset = str_data(src) - dst->heap.ptr;

  if (!_str_reserve(dst, new_len + 1))
    return 0;
  char* src_data = aliased ? dst->heap.ptr + alias_offset : str_data(src);

  memmove(dst->heap.ptr + old_len, src_data, src_len);
  dst->heap.ptr[new_len] = '\0';
  dst->heap.len = new_len;
  dst->heap.cap = new_len | FLAG_HEAP;
  return 1;
}

static inline int c_str_cat(String* dst, const char *src)
{
  String s = str(src);
  int res = str_cat(dst, &s);
  STR_FREE(s);
  return res;
}

static inline int str_empty(String s)
{
  return str_len(&s) == 0;
}