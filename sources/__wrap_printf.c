#include <stdio.h>

int __wrap_printf(const char *fmt, ...) { return 0; }
int __wrap_fprintf(FILE *f, const char *fmt, ...) { return 0; }
