
#ifndef _PRINT_COLUMNS_H_
#define _PRINT_COLUMNS_H_

#include <cfile.h>
#include <epan/epan.h>

gboolean print_columns(capture_file *cf, const epan_dissect_t *edt);
char* get_columns_cstr(capture_file *cf, const epan_dissect_t *edt);

#endif /* _PRINT_COLUMNS_H_ */
