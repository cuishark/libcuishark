/* cfile.c
 * capture_file GUI-independent manipulation
 * Vassilii Khachaturov <vassilii@tarunz.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <epan/packet.h>
/* #include <wiretap/pcapng.h> */

#include "cfile.h"
#include <stdbool.h>

void
cap_file_init(capture_file *cf)
{
  /* Initialize the capture file struct */
  memset(cf, 0, sizeof(capture_file));
}

gboolean
cf_read_record_r(capture_file *cf, const frame_data *fdata,
                 wtap_rec *rec, Buffer *buf)
{
  int    err;
  gchar *err_info;
  bool ret = wtap_seek_read(cf->provider.wth,
      fdata->file_off, rec, buf, &err, &err_info);
  return ret;
}

gboolean
cf_read_record(capture_file *cf, frame_data *fdata)
{
  return cf_read_record_r(cf, fdata, &cf->rec, &cf->buf);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
