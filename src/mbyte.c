__END_DECLS char_u *enc_locale(void)              {
  char        *s;
  char        *p;
  int i;
  char buf[50];
# ifdef HAVE_NL_LANGINFO_CODESET
  if ((s = nl_langinfo(CODESET)) == NULL || *s == NUL)
# endif
#  if defined(HAVE_LOCALE_H) || defined(X_LOCALE)
  if ((s = setlocale(LC_CTYPE, NULL)) == NULL || *s == NUL)
#  endif
  if ((s = getenv("LC_ALL")) == NULL || *s == NUL)
    if ((s = getenv("LC_CTYPE")) == NULL || *s == NUL)
      s = getenv("LANG");

  if (s == NULL || *s == NUL)
    return FAIL;

  /* The most generic locale format is:
   * language[_territory][.codeset][@modifier][+special][,[sponsor][_revision]]
   * If there is a '.' remove the part before it.
   * if there is something after the codeset, remove it.
   * Make the name lowercase and replace '_' with '-'.
   * Exception: "ja_JP.EUC" == "euc-jp", "zh_CN.EUC" = "euc-cn",
   * "ko_KR.EUC" == "euc-kr"
   */
  if ((p = (char *)vim_strchr((char_u *)s, '.')) != NULL) {
    if (p > s + 2 && STRNICMP(p + 1, "EUC", 3) == 0
        && !isalnum((int)p[4]) && p[4] != '-' && p[-3] == '_') {
      /* copy "XY.EUC" to "euc-XY" to buf[10] */
      STRCPY(buf + 10, "euc-");
      buf[14] = p[-2];
      buf[15] = p[-1];
      buf[16] = 0;
      s = buf + 10;
    } else
      s = p + 1;
  }
  for (i = 0; s[i] != NUL && i < (int)sizeof(buf) - 1; ++i) {
    if (s[i] == '_' || s[i] == '-')
      buf[i] = '-';
    else if (isalnum((int)s[i]))
      buf[i] = TOLOWER_ASC(s[i]);
    else
      break;
  }
  buf[i] = NUL;

  return enc_canonize((char_u *)buf);
}

# if defined(USE_ICONV) || defined(PROTO)

static char_u *
iconv_string __ARGS((vimconv_T *vcp, char_u *str, int slen, int *unconvlenp,
                     int *resultlenp));

/*
 * Call iconv_open() with a check if iconv() works properly (there are broken
 * versions).
 * Returns (void *)-1 if failed.
 * (should return iconv_t, but that causes problems with prototypes).
 */
void *my_iconv_open(char_u *to, char_u *from)
{
  iconv_t fd;
#define ICONV_TESTLEN 400
  char_u tobuf[ICONV_TESTLEN];
  char        *p;
  size_t tolen;
  static int iconv_ok = -1;

  if (iconv_ok == FALSE)
    return (void *)-1;          /* detected a broken iconv() previously */

#ifdef DYNAMIC_ICONV
  /* Check if the iconv.dll can be found. */
  if (!iconv_enabled(TRUE))
    return (void *)-1;
#endif

  fd = iconv_open((char *)enc_skip(to), (char *)enc_skip(from));

  if (fd != (iconv_t)-1 && iconv_ok == -1) {
    /*
     * Do a dummy iconv() call to check if it actually works.  There is a
     * version of iconv() on Linux that is broken.  We can't ignore it,
     * because it's wide-spread.  The symptoms are that after outputting
     * the initial shift state the "to" pointer is NULL and conversion
     * stops for no apparent reason after about 8160 characters.
     */
    p = (char *)tobuf;
    tolen = ICONV_TESTLEN;
    (void)iconv(fd, NULL, NULL, &p, &tolen);
    if (p == NULL) {
      iconv_ok = FALSE;
      iconv_close(fd);
      fd = (iconv_t)-1;
    } else
      iconv_ok = TRUE;
  }

  return (void *)fd;
}

/*
 * Convert the string "str[slen]" with iconv().
 * If "unconvlenp" is not NULL handle the string ending in an incomplete
 * sequence and set "*unconvlenp" to the length of it.
 * Returns the converted string in allocated memory.  NULL for an error.
 * If resultlenp is not NULL, sets it to the result length in bytes.
 */
static char_u * iconv_string(vcp, str, slen, unconvlenp, resultlenp)
vimconv_T   *vcp;
char_u      *str;
int slen;
int         *unconvlenp;
int         *resultlenp;
{
  const char  *from;
  size_t fromlen;
  char        *to;
  size_t tolen;
  size_t len = 0;
  size_t done = 0;
  char_u      *result = NULL;
  char_u      *p;
  int l;

  from = (char *)str;
  fromlen = slen;
  for (;; ) {
    if (len == 0 || ICONV_ERRNO == ICONV_E2BIG) {
      /* Allocate enough room for most conversions.  When re-allocating
       * increase the buffer size. */
      len = len + fromlen * 2 + 40;
      p = alloc((unsigned)len);
      if (p != NULL && done > 0)
        mch_memmove(p, result, done);
      vim_free(result);
      result = p;
      if (result == NULL)       /* out of memory */
        break;
    }

    to = (char *)result + done;
    tolen = len - done - 2;
    /* Avoid a warning for systems with a wrong iconv() prototype by
     * casting the second argument to void *. */
    if (iconv(vcp->vc_fd, (void *)&from, &fromlen, &to, &tolen)
        != (size_t)-1) {
      /* Finished, append a NUL. */
      *to = NUL;
      break;
    }

    /* Check both ICONV_EINVAL and EINVAL, because the dynamically loaded
     * iconv library may use one of them. */
    if (!vcp->vc_fail && unconvlenp != NULL
        && (ICONV_ERRNO == ICONV_EINVAL || ICONV_ERRNO == EINVAL)) {
      /* Handle an incomplete sequence at the end. */
      *to = NUL;
      *unconvlenp = (int)fromlen;
      break;
    }
    /* Check both ICONV_EILSEQ and EILSEQ, because the dynamically loaded
     * iconv library may use one of them. */
    else if (!vcp->vc_fail
             && (ICONV_ERRNO == ICONV_EILSEQ || ICONV_ERRNO == EILSEQ
                 || ICONV_ERRNO == ICONV_EINVAL || ICONV_ERRNO == EINVAL)) {
      /* Can't convert: insert a '?' and skip a character.  This assumes
       * conversion from 'encoding' to something else.  In other
       * situations we don't know what to skip anyway. */
      *to++ = '?';
      if ((*mb_ptr2cells)((char_u *)from) > 1)
        *to++ = '?';
      if (enc_utf8)
        l = utfc_ptr2len_len((char_u *)from, (int)fromlen);
      else {
        l = (*mb_ptr2len)((char_u *)from);
        if (l > (int)fromlen)
          l = (int)fromlen;
      }
      from += l;
      fromlen -= l;
    } else if (ICONV_ERRNO != ICONV_E2BIG)   {
      /* conversion failed */
      vim_free(result);
      result = NULL;
      break;
    }
    /* Not enough room or skipping illegal sequence. */
    done = to - (char *)result;
  }

  if (resultlenp != NULL && result != NULL)
    *resultlenp = (int)(to - (char *)result);
  return result;
}

#  if defined(DYNAMIC_ICONV) || defined(PROTO)
/*
 * Dynamically load the "iconv.dll" on Win32.
 */

#ifndef DYNAMIC_ICONV       /* just generating prototypes */
# define HINSTANCE int
#endif
static HINSTANCE hIconvDLL = 0;
static HINSTANCE hMsvcrtDLL = 0;

#  ifndef DYNAMIC_ICONV_DLL
#   define DYNAMIC_ICONV_DLL "iconv.dll"
#   define DYNAMIC_ICONV_DLL_ALT "libiconv.dll"
#  endif
#  ifndef DYNAMIC_MSVCRT_DLL
#   define DYNAMIC_MSVCRT_DLL "msvcrt.dll"
#  endif

/*
 * Get the address of 'funcname' which is imported by 'hInst' DLL.
 */
static void * get_iconv_import_func(HINSTANCE hInst,
    const char *funcname)                   {
  PBYTE pImage = (PBYTE)hInst;
  PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)hInst;
  PIMAGE_NT_HEADERS pPE;
  PIMAGE_IMPORT_DESCRIPTOR pImpDesc;
  PIMAGE_THUNK_DATA pIAT;                   /* Import Address Table */
  PIMAGE_THUNK_DATA pINT;                   /* Import Name Table */
  PIMAGE_IMPORT_BY_NAME pImpName;

  if (pDOS->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;
  pPE = (PIMAGE_NT_HEADERS)(pImage + pDOS->e_lfanew);
  if (pPE->Signature != IMAGE_NT_SIGNATURE)
    return NULL;
  pImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pImage
                                        + pPE->OptionalHeader.DataDirectory[
                                          IMAGE_DIRECTORY_ENTRY_IMPORT]
                                        .VirtualAddress);
  for (; pImpDesc->FirstThunk; ++pImpDesc) {
    if (!pImpDesc->OriginalFirstThunk)
      continue;
    pIAT = (PIMAGE_THUNK_DATA)(pImage + pImpDesc->FirstThunk);
    pINT = (PIMAGE_THUNK_DATA)(pImage + pImpDesc->OriginalFirstThunk);
    for (; pIAT->u1.Function; ++pIAT, ++pINT) {
      if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
        continue;
      pImpName = (PIMAGE_IMPORT_BY_NAME)(pImage
                                         + (UINT_PTR)(pINT->u1.AddressOfData));
      if (strcmp(pImpName->Name, funcname) == 0)
        return (void *)pIAT->u1.Function;
    }
  }
  return NULL;
}

/*
 * Try opening the iconv.dll and return TRUE if iconv() can be used.
 */
int iconv_enabled(int verbose)
{
  if (hIconvDLL != 0 && hMsvcrtDLL != 0)
    return TRUE;
  hIconvDLL = vimLoadLib(DYNAMIC_ICONV_DLL);
  if (hIconvDLL == 0)           /* sometimes it's called libiconv.dll */
    hIconvDLL = vimLoadLib(DYNAMIC_ICONV_DLL_ALT);
  if (hIconvDLL != 0)
    hMsvcrtDLL = vimLoadLib(DYNAMIC_MSVCRT_DLL);
  if (hIconvDLL == 0 || hMsvcrtDLL == 0) {
    /* Only give the message when 'verbose' is set, otherwise it might be
     * done whenever a conversion is attempted. */
    if (verbose && p_verbose > 0) {
      verbose_enter();
      EMSG2(_(e_loadlib),
          hIconvDLL == 0 ? DYNAMIC_ICONV_DLL : DYNAMIC_MSVCRT_DLL);
      verbose_leave();
    }
    iconv_end();
    return FALSE;
  }

  iconv       = (void *)GetProcAddress(hIconvDLL, "libiconv");
  iconv_open  = (void *)GetProcAddress(hIconvDLL, "libiconv_open");
  iconv_close = (void *)GetProcAddress(hIconvDLL, "libiconv_close");
  iconvctl    = (void *)GetProcAddress(hIconvDLL, "libiconvctl");
  iconv_errno = get_iconv_import_func(hIconvDLL, "_errno");
  if (iconv_errno == NULL)
    iconv_errno = (void *)GetProcAddress(hMsvcrtDLL, "_errno");
  if (iconv == NULL || iconv_open == NULL || iconv_close == NULL
      || iconvctl == NULL || iconv_errno == NULL) {
    iconv_end();
    if (verbose && p_verbose > 0) {
      verbose_enter();
      EMSG2(_(e_loadfunc), "for libiconv");
      verbose_leave();
    }
    return FALSE;
  }
  return TRUE;
}

void iconv_end(void)          {
  /* Don't use iconv() when inputting or outputting characters. */
  if (input_conv.vc_type == CONV_ICONV)
    convert_setup(&input_conv, NULL, NULL);
  if (output_conv.vc_type == CONV_ICONV)
    convert_setup(&output_conv, NULL, NULL);

  if (hIconvDLL != 0)
    FreeLibrary(hIconvDLL);
  if (hMsvcrtDLL != 0)
    FreeLibrary(hMsvcrtDLL);
  hIconvDLL = 0;
  hMsvcrtDLL = 0;
}

#  endif /* DYNAMIC_ICONV */
# endif /* USE_ICONV */




/*
 * Setup "vcp" for conversion from "from" to "to".
 * The names must have been made canonical with enc_canonize().
 * vcp->vc_type must have been initialized to CONV_NONE.
 * Note: cannot be used for conversion from/to ucs-2 and ucs-4 (will use utf-8
 * instead).
 * Afterwards invoke with "from" and "to" equal to NULL to cleanup.
 * Return FAIL when conversion is not supported, OK otherwise.
 */
int convert_setup(vcp, from, to)
vimconv_T   *vcp;
char_u      *from;
char_u      *to;
{
  return convert_setup_ext(vcp, from, TRUE, to, TRUE);
}

/*
 * As convert_setup(), but only when from_unicode_is_utf8 is TRUE will all
 * "from" unicode charsets be considered utf-8.  Same for "to".
 */
int convert_setup_ext(vcp, from, from_unicode_is_utf8, to, to_unicode_is_utf8)
vimconv_T   *vcp;
char_u      *from;
int from_unicode_is_utf8;
char_u      *to;
int to_unicode_is_utf8;
{
  int from_prop;
  int to_prop;
  int from_is_utf8;
  int to_is_utf8;

  /* Reset to no conversion. */
# ifdef USE_ICONV
  if (vcp->vc_type == CONV_ICONV && vcp->vc_fd != (iconv_t)-1)
    iconv_close(vcp->vc_fd);
# endif
  vcp->vc_type = CONV_NONE;
  vcp->vc_factor = 1;
  vcp->vc_fail = FALSE;

  /* No conversion when one of the names is empty or they are equal. */
  if (from == NULL || *from == NUL || to == NULL || *to == NUL
      || STRCMP(from, to) == 0)
    return OK;

  from_prop = enc_canon_props(from);
  to_prop = enc_canon_props(to);
  if (from_unicode_is_utf8)
    from_is_utf8 = from_prop & ENC_UNICODE;
  else
    from_is_utf8 = from_prop == ENC_UNICODE;
  if (to_unicode_is_utf8)
    to_is_utf8 = to_prop & ENC_UNICODE;
  else
    to_is_utf8 = to_prop == ENC_UNICODE;

  if ((from_prop & ENC_LATIN1) && to_is_utf8) {
    /* Internal latin1 -> utf-8 conversion. */
    vcp->vc_type = CONV_TO_UTF8;
    vcp->vc_factor = 2;         /* up to twice as long */
  } else if ((from_prop & ENC_LATIN9) && to_is_utf8)   {
    /* Internal latin9 -> utf-8 conversion. */
    vcp->vc_type = CONV_9_TO_UTF8;
    vcp->vc_factor = 3;         /* up to three as long (euro sign) */
  } else if (from_is_utf8 && (to_prop & ENC_LATIN1))   {
    /* Internal utf-8 -> latin1 conversion. */
    vcp->vc_type = CONV_TO_LATIN1;
  } else if (from_is_utf8 && (to_prop & ENC_LATIN9))   {
    /* Internal utf-8 -> latin9 conversion. */
    vcp->vc_type = CONV_TO_LATIN9;
  }
# ifdef USE_ICONV
  else {
    /* Use iconv() for conversion. */
    vcp->vc_fd = (iconv_t)my_iconv_open(
        to_is_utf8 ? (char_u *)"utf-8" : to,
        from_is_utf8 ? (char_u *)"utf-8" : from);
    if (vcp->vc_fd != (iconv_t)-1) {
      vcp->vc_type = CONV_ICONV;
      vcp->vc_factor = 4;       /* could be longer too... */
    }
  }
# endif
  if (vcp->vc_type == CONV_NONE)
    return FAIL;

  return OK;
}

#if defined(FEAT_GUI) || defined(AMIGA) || defined(WIN3264) \
  || defined(MSDOS) || defined(PROTO)
/*
 * Do conversion on typed input characters in-place.
 * The input and output are not NUL terminated!
 * Returns the length after conversion.
 */
int convert_input(char_u *ptr, int len, int maxlen)
{
  return convert_input_safe(ptr, len, maxlen, NULL, NULL);
}
#endif

/*
 * Like convert_input(), but when there is an incomplete byte sequence at the
 * end return that as an allocated string in "restp" and set "*restlenp" to
 * the length.  If "restp" is NULL it is not used.
 */
int convert_input_safe(char_u *ptr, int len, int maxlen, char_u **restp, int *restlenp)
{
  char_u      *d;
  int dlen = len;
  int unconvertlen = 0;

  d = string_convert_ext(&input_conv, ptr, &dlen,
      restp == NULL ? NULL : &unconvertlen);
  if (d != NULL) {
    if (dlen <= maxlen) {
      if (unconvertlen > 0) {
        /* Move the unconverted characters to allocated memory. */
        *restp = alloc(unconvertlen);
        if (*restp != NULL)
          mch_memmove(*restp, ptr + len - unconvertlen, unconvertlen);
        *restlenp = unconvertlen;
      }
      mch_memmove(ptr, d, dlen);
    } else
      /* result is too long, keep the unconverted text (the caller must
       * have done something wrong!) */
      dlen = len;
    vim_free(d);
  }
  return dlen;
}

/*
 * Convert text "ptr[*lenp]" according to "vcp".
 * Returns the result in allocated memory and sets "*lenp".
 * When "lenp" is NULL, use NUL terminated strings.
 * Illegal chars are often changed to "?", unless vcp->vc_fail is set.
 * When something goes wrong, NULL is returned and "*lenp" is unchanged.
 */
char_u * string_convert(vcp, ptr, lenp)
vimconv_T   *vcp;
char_u      *ptr;
int         *lenp;
{
  return string_convert_ext(vcp, ptr, lenp, NULL);
}

/*
 * Like string_convert(), but when "unconvlenp" is not NULL and there are is
 * an incomplete sequence at the end it is not converted and "*unconvlenp" is
 * set to the number of remaining bytes.
 */
char_u * string_convert_ext(vcp, ptr, lenp, unconvlenp)
vimconv_T   *vcp;
char_u      *ptr;
int         *lenp;
int         *unconvlenp;
{
  char_u      *retval = NULL;
  char_u      *d;
  int len;
  int i;
  int l;
  int c;

  if (lenp == NULL)
    len = (int)STRLEN(ptr);
  else
    len = *lenp;
  if (len == 0)
    return vim_strsave((char_u *)"");

  switch (vcp->vc_type) {
  case CONV_TO_UTF8:            /* latin1 to utf-8 conversion */
    retval = alloc(len * 2 + 1);
    if (retval == NULL)
      break;
    d = retval;
    for (i = 0; i < len; ++i) {
      c = ptr[i];
      if (c < 0x80)
        *d++ = c;
      else {
        *d++ = 0xc0 + ((unsigned)c >> 6);
        *d++ = 0x80 + (c & 0x3f);
      }
    }
    *d = NUL;
    if (lenp != NULL)
      *lenp = (int)(d - retval);
    break;

  case CONV_9_TO_UTF8:          /* latin9 to utf-8 conversion */
    retval = alloc(len * 3 + 1);
    if (retval == NULL)
      break;
    d = retval;
    for (i = 0; i < len; ++i) {
      c = ptr[i];
      switch (c) {
      case 0xa4: c = 0x20ac; break;                 /* euro */
      case 0xa6: c = 0x0160; break;                 /* S hat */
      case 0xa8: c = 0x0161; break;                 /* S -hat */
      case 0xb4: c = 0x017d; break;                 /* Z hat */
      case 0xb8: c = 0x017e; break;                 /* Z -hat */
      case 0xbc: c = 0x0152; break;                 /* OE */
      case 0xbd: c = 0x0153; break;                 /* oe */
      case 0xbe: c = 0x0178; break;                 /* Y */
      }
      d += utf_char2bytes(c, d);
    }
    *d = NUL;
    if (lenp != NULL)
      *lenp = (int)(d - retval);
    break;

  case CONV_TO_LATIN1:          /* utf-8 to latin1 conversion */
  case CONV_TO_LATIN9:          /* utf-8 to latin9 conversion */
    retval = alloc(len + 1);
    if (retval == NULL)
      break;
    d = retval;
    for (i = 0; i < len; ++i) {
      l = utf_ptr2len_len(ptr + i, len - i);
      if (l == 0)
        *d++ = NUL;
      else if (l == 1) {
        int l_w = utf8len_tab_zero[ptr[i]];

        if (l_w == 0) {
          /* Illegal utf-8 byte cannot be converted */
          vim_free(retval);
          return NULL;
        }
        if (unconvlenp != NULL && l_w > len - i) {
          /* Incomplete sequence at the end. */
          *unconvlenp = len - i;
          break;
        }
        *d++ = ptr[i];
      } else   {
        c = utf_ptr2char(ptr + i);
        if (vcp->vc_type == CONV_TO_LATIN9)
          switch (c) {
          case 0x20ac: c = 0xa4; break;                     /* euro */
          case 0x0160: c = 0xa6; break;                     /* S hat */
          case 0x0161: c = 0xa8; break;                     /* S -hat */
          case 0x017d: c = 0xb4; break;                     /* Z hat */
          case 0x017e: c = 0xb8; break;                     /* Z -hat */
          case 0x0152: c = 0xbc; break;                     /* OE */
          case 0x0153: c = 0xbd; break;                     /* oe */
          case 0x0178: c = 0xbe; break;                     /* Y */
          case 0xa4:
          case 0xa6:
          case 0xa8:
          case 0xb4:
          case 0xb8:
          case 0xbc:
          case 0xbd:
          case 0xbe: c = 0x100; break;                   /* not in latin9 */
          }
        if (!utf_iscomposing(c)) {              /* skip composing chars */
          if (c < 0x100)
            *d++ = c;
          else if (vcp->vc_fail) {
            vim_free(retval);
            return NULL;
          } else   {
            *d++ = 0xbf;
            if (utf_char2cells(c) > 1)
              *d++ = '?';
          }
        }
        i += l - 1;
      }
    }
    *d = NUL;
    if (lenp != NULL)
      *lenp = (int)(d - retval);
    break;

# ifdef MACOS_CONVERT
  case CONV_MAC_LATIN1:
    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail,
        'm', 'l', unconvlenp);
    break;

  case CONV_LATIN1_MAC:
    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail,
        'l', 'm', unconvlenp);
    break;

  case CONV_MAC_UTF8:
    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail,
        'm', 'u', unconvlenp);
    break;

  case CONV_UTF8_MAC:
    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail,
        'u', 'm', unconvlenp);
    break;
# endif

# ifdef USE_ICONV
  case CONV_ICONV:              /* conversion with output_conv.vc_fd */
    retval = iconv_string(vcp, ptr, len, unconvlenp, lenp);
    break;
# endif
  }

  return retval;
}
