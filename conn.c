#include <openssl/err.h>
#include <openssl/ssl.h>
#include "_cgo_export.h"
#include "conn.h"
#include <stdio.h>

// Set error message in err
void set_error_message(SSLFuncError *err) {
    int result;
    err->error_message = (char *)calloc(256, sizeof(char));
    result = ERR_get_error();
    ERR_error_string_n(result, err->error_message, 255);
}

// Handle error codes
void process_error_code(SSLFuncError *err, const SSL *ssl, int ret) {
    int has_error;
    err->error_code = SSL_get_error(ssl, ret);
    switch(err->error_code) {
    	case SSL_ERROR_NONE:
    		break;
    	case SSL_ERROR_ZERO_RETURN:
    		break;
    	case SSL_ERROR_WANT_READ:
    	    break;
    	case SSL_ERROR_WANT_WRITE:
    	    break;
    	case SSL_ERROR_SYSCALL:
    	    has_error = 0;
    	    if (ERR_peek_error() == 0) {
    	    	switch(ret) {
    	    		case 0:
                    case -1:
                        err->has_errno = 1;
    	    			has_error = 1;
    	    			break;
    	    	}
    	    }
    	    if (has_error == 0) {
        	    set_error_message(err);
    	    }
    	    break;
    	default:
    	    set_error_message(err);
    		break;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
    ERR_remove_state(0);
#else
    ERR_remove_thread_state(NULL);
#endif
}


// Read and return error
int SSL_read_with_error(SSL *ssl, void *buf, int num, SSLFuncError *err) {
    int ret;
    ret = SSL_read(ssl, buf, num);
    if (ret < 1) {
        process_error_code(err, ssl, ret);
    }
    return ret;
}

// Write and return error
int SSL_write_with_error(SSL *ssl, void *buf, int num, SSLFuncError *err) {
    int ret;
    ret = SSL_write(ssl, buf, num);
    if (ret < 1) {
        process_error_code(err, ssl, ret);
    }
    return ret;
}

// Handshake and return error
int SSL_handshake_with_error(SSL *ssl, SSLFuncError *err) {
    int ret;
    ret = SSL_do_handshake(ssl);
    if (ret < 1) {
        process_error_code(err, ssl, ret);
    }
    return ret;
}

// Shutdown and return error
int SSL_shutdown_with_error(SSL *ssl, SSLFuncError *err) {
    int ret;
    ret = SSL_shutdown(ssl);
    if (ret < 0) {
        process_error_code(err, ssl, ret);
    }
    return ret;
}
