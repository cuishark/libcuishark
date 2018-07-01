
#include <cuishark_includes.h>

static const nstime_t *
tshark_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;

  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;

  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;

  if (prov->frames) {
     frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

epan_t *
tshark_epan_new(capture_file *cf)
{
  static const struct packet_provider_funcs funcs = {
    tshark_get_frame_ts,
    cap_file_provider_get_interface_name,
    cap_file_provider_get_interface_description,
    NULL,
  };

  return epan_new(&cf->provider, &funcs);
}

void reset_epan_mem(capture_file *cf,epan_dissect_t *edt, gboolean tree, gboolean visual)
{
  const guint32 epan_auto_reset_count = 0;
  const gboolean epan_auto_reset = FALSE;
  if (!epan_auto_reset || (cf->count < epan_auto_reset_count))
    return;

  fprintf(stderr, "resetting session.\n");
  epan_dissect_cleanup(edt);
  epan_free(cf->epan);

  cf->epan = tshark_epan_new(cf);
  epan_dissect_init(edt, cf->epan, tree, visual);
  cf->count = 0;
}

void
cf_close(capture_file *cf)
{
  g_free(cf->filename);
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  gchar *err_info;
  const gboolean perform_two_pass_analysis = FALSE;
  wtap* wth = wtap_open_offline(fname, type, err, &err_info, perform_two_pass_analysis);
  if (wth == NULL)
    goto fail;

  epan_free(cf->epan);
  cf->epan = tshark_epan_new(cf);
  cf->provider.wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  cf->filename = g_strdup(fname);
  cf->is_tempfile = is_tempfile;
  cf->unsaved_changes = FALSE; /* No user changes yet. */

  cf->cd_t      = wtap_file_type_subtype(cf->provider.wth);
  cf->open_type = type;
  cf->count     = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->provider.wth);
  nstime_set_zero(&cf->elapsed_time);
  cf->provider.ref = NULL;
  cf->provider.prev_dis = NULL;
  cf->provider.prev_cap = NULL;
  cf->state = FILE_READ_IN_PROGRESS;

  wtap_set_cb_new_ipv4(cf->provider.wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->provider.wth, (wtap_new_ipv6_callback_t) add_ipv6_name);

  return CF_OK;

fail:
  cfile_open_failure_message("TShark", fname, *err, err_info);
  return CF_ERROR;
}

