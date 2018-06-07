
#include <cuishark_includes.h>
#include <print_columns.h>

static const gchar* delimiter_char = " ";
static const gboolean dissect_color = FALSE;

static char *
get_line_buf(size_t len)
{
  static char   *line_bufp    = NULL;
  static size_t  line_buf_len = 256;
  size_t         new_line_buf_len;

  for (new_line_buf_len = line_buf_len; len > new_line_buf_len;
       new_line_buf_len *= 2)
    ;
  if (line_bufp == NULL) {
    line_buf_len = new_line_buf_len;
    line_bufp = (char *)g_malloc(line_buf_len + 1);
  } else {
    if (new_line_buf_len > line_buf_len) {
      line_buf_len = new_line_buf_len;
      line_bufp = (char *)g_realloc(line_bufp, line_buf_len + 1);
    }
  }
  return line_bufp;
}

static inline void
put_string(char *dest, const char *str, size_t str_len)
{
  memcpy(dest, str, str_len);
  dest[str_len] = '\0';
}

static inline void
put_spaces_string(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
  size_t i;

  for (i = str_len; i < str_with_spaces; i++)
    *dest++ = ' ';

  put_string(dest, str, str_len);
}

static inline void
put_string_spaces(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
  memcpy(dest, str, str_len);
  for (size_t i = str_len; i < str_with_spaces; i++)
    dest[i] = ' ';
  dest[str_with_spaces] = '\0';
}

gboolean
print_columns(capture_file *cf, const epan_dissect_t *edt)
{
  char   *line_bufp;
  int     i;
  size_t  buf_offset;
  size_t  column_len;
  size_t  col_len;
  col_item_t* col_item;
  gchar str_format[11];
  const color_filter_t *color_filter = NULL;

  line_bufp = get_line_buf(256);
  buf_offset = 0;
  *line_bufp = '\0';

  if (dissect_color)
    color_filter = edt->pi.fd->color_filter;

  for (i = 0; i < cf->cinfo.num_cols; i++) {
    col_item = &cf->cinfo.columns[i];
    /* Skip columns not marked as visible. */
    if (!get_column_visible(i))
      continue;
    switch (col_item->col_fmt) {
    case COL_NUMBER:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 5)
        column_len = 5;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_CLS_TIME:
    case COL_REL_TIME:
    case COL_ABS_TIME:
    case COL_ABS_YMD_TIME:  /* XXX - wider */
    case COL_ABS_YDOY_TIME: /* XXX - wider */
    case COL_UTC_TIME:
    case COL_UTC_YMD_TIME:  /* XXX - wider */
    case COL_UTC_YDOY_TIME: /* XXX - wider */
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 10)
        column_len = 10;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string_spaces(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    default:
      column_len = strlen(col_item->col_data);
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string(line_bufp + buf_offset, col_item->col_data, column_len);
      break;
    }
    buf_offset += column_len;
    if (i != cf->cinfo.num_cols - 1) {
      /*
       * This isn't the last column, so we need to print a
       * separator between this column and the next.
       *
       * If we printed a network source and are printing a
       * network destination of the same type next, separate
       * them with a UTF-8 right arrow; if we printed a network
       * destination and are printing a network source of the same
       * type next, separate them with a UTF-8 left arrow;
       * otherwise separate them with a space.
       *
       * We add enough space to the buffer for " \xe2\x86\x90 "
       * or " \xe2\x86\x92 ", even if we're only adding " ".
       */
      line_bufp = get_line_buf(buf_offset + 5);
      switch (col_item->col_fmt) {

      case COL_DEF_SRC:
      case COL_RES_SRC:
      case COL_UNRES_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DST:
        case COL_RES_DST:
        case COL_UNRES_DST:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DL_SRC:
      case COL_RES_DL_SRC:
      case COL_UNRES_DL_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_DST:
        case COL_RES_DL_DST:
        case COL_UNRES_DL_DST:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_NET_SRC:
      case COL_RES_NET_SRC:
      case COL_UNRES_NET_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_DST:
        case COL_RES_NET_DST:
        case COL_UNRES_NET_DST:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DST:
      case COL_RES_DST:
      case COL_UNRES_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_SRC:
        case COL_RES_SRC:
        case COL_UNRES_SRC:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DL_DST:
      case COL_RES_DL_DST:
      case COL_UNRES_DL_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_SRC:
        case COL_RES_DL_SRC:
        case COL_UNRES_DL_SRC:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_NET_DST:
      case COL_RES_NET_DST:
      case COL_UNRES_NET_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_SRC:
        case COL_RES_NET_SRC:
        case COL_UNRES_NET_SRC:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      default:
        put_string(line_bufp + buf_offset, delimiter_char, 1);
        buf_offset += 1;
        break;
      }
    }
  }

  print_stream_t *print_stream = print_stream_text_stdio_new(stdout);
  if (dissect_color && color_filter != NULL)
    return print_line_color(print_stream, 0, line_bufp, &color_filter->fg_color, &color_filter->bg_color);
  else
    return print_line(print_stream, 0, line_bufp);
}


char*
get_columns_cstr(capture_file *cf, const epan_dissect_t *edt)
{
  char   *line_bufp;
  int     i;
  size_t  buf_offset;
  size_t  column_len;
  size_t  col_len;
  col_item_t* col_item;
  gchar str_format[11];
  const color_filter_t *color_filter = NULL;

  line_bufp = get_line_buf(256);
  buf_offset = 0;
  *line_bufp = '\0';

  if (dissect_color)
    color_filter = edt->pi.fd->color_filter;

  for (i = 0; i < cf->cinfo.num_cols; i++) {
    col_item = &cf->cinfo.columns[i];
    /* Skip columns not marked as visible. */
    if (!get_column_visible(i))
      continue;
    switch (col_item->col_fmt) {
    case COL_NUMBER:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 5)
        column_len = 5;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_CLS_TIME:
    case COL_REL_TIME:
    case COL_ABS_TIME:
    case COL_ABS_YMD_TIME:  /* XXX - wider */
    case COL_ABS_YDOY_TIME: /* XXX - wider */
    case COL_UTC_TIME:
    case COL_UTC_YMD_TIME:  /* XXX - wider */
    case COL_UTC_YDOY_TIME: /* XXX - wider */
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 10)
        column_len = 10;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string_spaces(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    default:
      column_len = strlen(col_item->col_data);
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string(line_bufp + buf_offset, col_item->col_data, column_len);
      break;
    }
    buf_offset += column_len;
    if (i != cf->cinfo.num_cols - 1) {
      /*
       * This isn't the last column, so we need to print a
       * separator between this column and the next.
       *
       * If we printed a network source and are printing a
       * network destination of the same type next, separate
       * them with a UTF-8 right arrow; if we printed a network
       * destination and are printing a network source of the same
       * type next, separate them with a UTF-8 left arrow;
       * otherwise separate them with a space.
       *
       * We add enough space to the buffer for " \xe2\x86\x90 "
       * or " \xe2\x86\x92 ", even if we're only adding " ".
       */
      line_bufp = get_line_buf(buf_offset + 5);
      switch (col_item->col_fmt) {

      case COL_DEF_SRC:
      case COL_RES_SRC:
      case COL_UNRES_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DST:
        case COL_RES_DST:
        case COL_UNRES_DST:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DL_SRC:
      case COL_RES_DL_SRC:
      case COL_UNRES_DL_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_DST:
        case COL_RES_DL_DST:
        case COL_UNRES_DL_DST:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_NET_SRC:
      case COL_RES_NET_SRC:
      case COL_UNRES_NET_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_DST:
        case COL_RES_NET_DST:
        case COL_UNRES_NET_DST:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_RIGHTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DST:
      case COL_RES_DST:
      case COL_UNRES_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_SRC:
        case COL_RES_SRC:
        case COL_UNRES_SRC:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DL_DST:
      case COL_RES_DL_DST:
      case COL_UNRES_DL_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_SRC:
        case COL_RES_DL_SRC:
        case COL_UNRES_DL_SRC:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_NET_DST:
      case COL_RES_NET_DST:
      case COL_UNRES_NET_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_SRC:
        case COL_RES_NET_SRC:
        case COL_UNRES_NET_SRC:
          g_snprintf(str_format, sizeof(str_format), "%s%s%s", delimiter_char, UTF8_LEFTWARDS_ARROW, delimiter_char);
          put_string(line_bufp + buf_offset, str_format, 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, delimiter_char, 1);
          buf_offset += 1;
          break;
        }
        break;

      default:
        put_string(line_bufp + buf_offset, delimiter_char, 1);
        buf_offset += 1;
        break;
      }
    }
  }

  return line_bufp;
}
