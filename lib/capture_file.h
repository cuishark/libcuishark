
#ifndef _CAPTURE_FILE_H_
#define _CAPTURE_FILE_H_

#include <cfile.h>
#include <epan/epan.h>

epan_t * tshark_epan_new(capture_file *cf);
void cf_close(capture_file* cf);
cf_status_t cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err);
void reset_epan_mem(capture_file *cf, epan_dissect_t *edt, gboolean tree, gboolean visual);

#endif /* _CAPTURE_FILE_H_ */
