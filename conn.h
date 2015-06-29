#ifndef conn_h
#define conn_h

typedef struct {
	long error_code;
	int has_errno;
	char *error_message;
} SSLFuncError;
#endif
