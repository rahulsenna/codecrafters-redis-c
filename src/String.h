#pragma once
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stddef.h>

#define SSO_MAX 15

typedef enum { STR_KIND_SSO = 0, STR_KIND_HEAP, STR_KIND_VIEW } StrKind;
typedef struct String
{
  size_t len;
  union
  {
    char buf[SSO_MAX + 1];
    struct
    {
      char* ptr;
      size_t cap;
    };
  };
  StrKind kind;
} String;


static inline String _str_view(const char* cstr, size_t n)
{
  String out = { 0 };
  out.len = n;
  out.ptr = (char*) cstr;
  out.cap = 0;
  out.kind = STR_KIND_VIEW;
  return out;
}

static inline String _str_cpy(const char* cstr, size_t n)
{
  String out = { 0 };
  out.len = n;
  if (n <= SSO_MAX)
  {
    out.kind = STR_KIND_SSO;
    memcpy(out.buf, (cstr), n);
    out.buf[n] = '\0';
    return out;
  }

  out.kind = STR_KIND_HEAP;
  out.cap = n + 1;
  out.ptr = (char*) malloc(n + 1);
  memcpy(out.ptr, cstr, n);
  out.ptr[n] = '\0';
  return out;
}

/* init *String* from length, fill in data later */
static inline String str_init_len(size_t n)
{
  String out = { 0 };
  out.len = n;
  if (n <= SSO_MAX)
  {
    out.kind = STR_KIND_SSO;
    out.buf[n] = '\0';
    return out;
  }

  out.kind = STR_KIND_HEAP;
  out.cap = n + 1;
  out.ptr = (char*) malloc(n + 1);
  out.ptr[n] = '\0';
  return out;
}

#define STR_IS_SSO(s)   ((s).kind == STR_KIND_SSO)
#define STR_IS_VIEW(s)  ((s).kind == STR_KIND_VIEW)
#define STR_IS_HEAP(s)  ((s).kind == STR_KIND_HEAP)

static inline char* str_data(String* s)
{
  return s->kind == STR_KIND_SSO ? s->buf : s->ptr;
}
#define STR_DATA(s) (str_data(&s))

#define STR_FREE(s)                     \
    do {                                \
        if (!STR_IS_SSO(s) &&           \
            !STR_IS_VIEW(s))            \
            free((s).ptr);              \
        (s).len = 0;                    \
        (s).kind = STR_KIND_SSO;        \
        (s).buf[0] = '\0';              \
    } while (0)

static inline String str_clone(String s)
{
  return _str_cpy(str_data(&s), s.len);
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
  return _str_view_from_cstr((const char*) s);
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
  return a.len == b.len && *str_data(&a) == *str_data(&b) && memcmp(str_data(&a), str_data(&b), a.len) == 0;
}
static inline int c_str_eq(String a, char* b)
{
  return a.len == strlen(b) && *str_data(&a) == *b && memcmp(str_data(&a), b, a.len) == 0;
}

static inline int _str_reserve(String* s, size_t need)
{
  if (need <= SSO_MAX + 1 && !STR_IS_HEAP(*s))
    return 1;

  if (STR_IS_HEAP(*s))
  {
    if (s->cap >= need)
      return 1;

    char* p = (char*) realloc(s->ptr, need);
    if (!p)
      return 0;

    s->ptr = p;
    s->cap = need;
    return 1;
  }

  char* p = (char*) malloc(need);
  if (!p)
    return 0;

  memcpy(p, str_data(s), s->len);
  p[s->len] = '\0';
  s->ptr = p;
  s->cap = need;
  s->kind = STR_KIND_HEAP;
  return 1;
}

static inline int str_cat(String* dst, String src)
{
  size_t old_len = dst->len;
  size_t new_len = old_len + src.len;

  if (new_len <= SSO_MAX)
  {
    char* src_data = str_data(&src);
    if (STR_IS_VIEW(*dst))
    {
      const char* view_ptr = dst->ptr;
      memmove(dst->buf, view_ptr, dst->len);
      dst->kind = STR_KIND_SSO;
    }
    memmove(dst->buf + old_len, src_data, src.len);
    dst->buf[new_len] = '\0';
    dst->len = new_len;
    return 1;
  }

  ptrdiff_t alias_offset = 0;
  int aliased = STR_IS_HEAP(*dst) && str_data(&src) >= dst->ptr && str_data(&src) < dst->ptr + dst->len;
  if (aliased)
    alias_offset = str_data(&src) - dst->ptr;

  if (!_str_reserve(dst, new_len + 1))
    return 0;
  char* src_data = aliased ? dst->ptr + alias_offset : str_data(&src);

  memmove(dst->ptr + old_len, src_data, src.len);
  dst->ptr[new_len] = '\0';
  dst->len = new_len;
  dst->kind = STR_KIND_HEAP;
  return 1;
}


#define str_empty(s)       ((s).len == 0)