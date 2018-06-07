
#ifndef _CUISHARK_TYPES_H_
#define _CUISHARK_TYPES_H_

#define LOG_DOMAIN_CAPTURE "Capture"
#ifdef HAVE_PCAP_OPEN_DEAD
#undef HAVE_PCAP_OPEN_DEAD
#endif

#define LONGOPT_COLOR (65536+1000)
#define LONGOPT_NO_DUPLICATE_KEYS (65536+1001)

/* Exit codes */
#define INVALID_OPTION 1
#define INVALID_INTERFACE 2
#define INVALID_FILE 2
#define INVALID_FILTER 2
#define INVALID_EXPORT 2
#define INVALID_CAPABILITY 2
#define INVALID_TAP 2
#define INVALID_DATA_LINK 2
#define INVALID_TIMESTAMP_TYPE 2
#define INVALID_CAPTURE 2
#define INIT_FAILED 2

struct string_elem {
  const char *sstr;   /* The short string */
  const char *lstr;   /* The long string */
};


#endif /* _CUISHARK_TYPES_H_ */
