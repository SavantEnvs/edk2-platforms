/* libc side of the selftest (kept apart: libc headers clash with EDK2 types). */
#include <stdio.h>
#include <stdlib.h>

unsigned char *
selftest_load (const char *path, unsigned long *size)
{
  FILE           *f = fopen (path, "rb");
  unsigned char  *buf;
  long           n;

  if (f == NULL) {
    return NULL;
  }

  fseek (f, 0, SEEK_END);
  n = ftell (f);
  fseek (f, 0, SEEK_SET);
  buf = malloc (n > 0 ? n : 1);
  if ((buf == NULL) || (fread (buf, 1, n, f) != (size_t)n)) {
    fclose (f);
    free (buf);
    return NULL;
  }

  fclose (f);
  *size = (unsigned long)n;
  return buf;
}

void
selftest_report (const char *name, int ok)
{
  printf ("%s %s\n", ok ? "PASS" : "FAIL", name);
}

void
selftest_note (const char *what, const unsigned short *s)
{
  printf ("  %s: ", what);
  for ( ; s && *s; s++) {
    putchar (*s < 128 ? *s : '?');
  }

  putchar ('\n');
}

void
selftest_hex (unsigned char b)
{
  printf ("  block byte: %02x\n", b);
}
