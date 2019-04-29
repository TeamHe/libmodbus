#include <glib.h>
#include <gio/gio.h>
#include <stdio.h>
#include <errno.h>
#include "modbus.h"
#include "modbus-private.h" 

/* Internal use */
#define MSG_LENGTH_UNDEFINED -1

#define MAX_MESSAGE_LENGTH 260

/* 3 steps are used to parse the query */
typedef enum {
    _STEP_FUNCTION,
    _STEP_META,
    _STEP_DATA
} _step_t;

typedef int (*sr_receive_data_callback)(int fd, int revents, void *cb_data);

//typedef void (*sr_datafeed_callback)(const struct sr_dev_inst *sdi,
//		const struct sr_datafeed_packet *packet, void *cb_data);
/**
 * @file
 *
 * Creating, using, or destroying libsigrok sessions.
 */

/**
 * @defgroup grp_session Session handling
 *
 * Creating, using, or destroying libsigrok sessions.
 *
 * @{
 */

//struct datafeed_callback {
//	sr_datafeed_callback cb;
//	void *cb_data;
//};

/** Custom GLib event source for generic descriptor I/O.
 * @see https://developer.gnome.org/glib/stable/glib-The-Main-Event-Loop.html
 * @internal
 */
struct fd_source {
	GSource base;

	int64_t timeout_us;
	int64_t due_us;

	/* Meta-data needed to keep track of installed sources */
	modbus_t *ctx;
	void *key;

	GPollFD pollfd;
};

/** FD event source prepare() method.
 * This is called immediately before poll().
 */
static gboolean fd_source_prepare(GSource *source, int *timeout)
{
	int64_t now_us;
	struct fd_source *fsource;
	int remaining_ms;

	fsource = (struct fd_source *)source;

	if (fsource->timeout_us >= 0) {
		now_us = g_source_get_time(source);

		if (fsource->due_us == 0) {
			/* First-time initialization of the expiration time */
			fsource->due_us = now_us + fsource->timeout_us;
		}
		remaining_ms = (MAX(0, fsource->due_us - now_us) + 999) / 1000;
	} else {
		remaining_ms = -1;
	}
	*timeout = remaining_ms;

	return (remaining_ms == 0);
}

/** FD event source check() method.
 * This is called after poll() returns to check whether an event fired.
 */
static gboolean fd_source_check(GSource *source)
{
	struct fd_source *fsource;
	unsigned int revents;

	fsource = (struct fd_source *)source;
	revents = fsource->pollfd.revents;

	return (revents != 0 || (fsource->timeout_us >= 0
			&& fsource->due_us <= g_source_get_time(source)));
}

/** FD event source dispatch() method.
 * This is called if either prepare() or check() returned TRUE.
 */
static gboolean fd_source_dispatch(GSource *source,
		GSourceFunc callback, void *user_data)
{
	struct fd_source *fsource;
	unsigned int revents;
	gboolean keep;

	fsource = (struct fd_source *)source;
	revents = fsource->pollfd.revents;

	if (!callback) {
//		sr_err("Callback not set, cannot dispatch event.");
		return G_SOURCE_REMOVE;
	}
	keep = (*(sr_receive_data_callback)callback)
			(fsource->pollfd.fd, revents, user_data);

	if (fsource->timeout_us >= 0 && G_LIKELY(keep)
			&& G_LIKELY(!g_source_is_destroyed(source)))
		fsource->due_us = g_source_get_time(source)
				+ fsource->timeout_us;
	return keep;
}

/** FD event source finalize() method.
 */
static void fd_source_finalize(GSource *source)
{
	struct fd_source *fsource;

	fsource = (struct fd_source *)source;

	g_source_unref(source);
}

static void fd_source_set_timeout(GSource *source,uint64_t timeout_us){
	struct fd_source *fsource = (struct fd_source *)source;
	fsource->timeout_us = timeout_us;
}

/** Create an event source for I/O on a file descriptor.
 *
 * In order to maintain API compatibility, this event source also doubles
 * as a timer event source.
 *
 * @param session The session the event source belongs to.
 * @param key The key used to identify this source.
 * @param fd The file descriptor or HANDLE.
 * @param timeout_us The timeout interval in us, or -1 to wait indefinitely.
 * @return A new event source object, or NULL on failure.
 */
static GSource *fd_source_new(modbus_t *ctx,
		int events, guint64 timeout_us )
{
	static GSourceFuncs fd_source_funcs = {
		.prepare  = &fd_source_prepare,
		.check    = &fd_source_check,
		.dispatch = &fd_source_dispatch,
		.finalize = &fd_source_finalize
	};
	GSource *source;
	struct fd_source *fsource;

	source = g_source_new(&fd_source_funcs, sizeof(struct fd_source));
	fsource = (struct fd_source *)source;

//	g_source_set_name(source, (fd < 0) ? "timer" : "fd");

	if (timeout_us >= 0) {
		fsource->timeout_us = timeout_us;
		fsource->due_us = 0;
	} else {
		fsource->timeout_us = -1;
		fsource->due_us = G_MAXINT64;
	}
	fsource->ctx = ctx;
	//fsource->key = key;

	fsource->pollfd.fd = ctx->s;
	fsource->pollfd.events = events;
	fsource->pollfd.revents = 0;

	if (ctx->s >= 0)
		g_source_add_poll(source, &fsource->pollfd);

	return source;
}

static void _sleep_response_timeout(modbus_t *ctx)
{
    /* Response timeout is always positive */
#ifdef _WIN32
    /* usleep doesn't exist on Windows */
    Sleep((ctx->response_timeout.tv_sec * 1000) +
          (ctx->response_timeout.tv_usec / 1000));
#else
    /* usleep source code */
    struct timespec request, remaining;
    request.tv_sec = ctx->response_timeout.tv_sec;
    request.tv_nsec = ((long int)ctx->response_timeout.tv_usec) * 1000;
    while (nanosleep(&request, &remaining) == -1 && errno == EINTR) {
        request = remaining;
    }
#endif
}

/*
 *  ---------- Request     Indication ----------
 *  | Client | ---------------------->| Server |
 *  ---------- Confirmation  Response ----------
 */

/* Computes the length to read after the function received */
static uint8_t compute_meta_length_after_function(int function,
                                                  msg_type_t msg_type)
{
    int length;

    if (msg_type == MSG_INDICATION) {
        if (function <= MODBUS_FC_WRITE_SINGLE_REGISTER) {
            length = 4;
        } else if (function == MODBUS_FC_WRITE_MULTIPLE_COILS ||
                   function == MODBUS_FC_WRITE_MULTIPLE_REGISTERS) {
            length = 5;
        } else if (function == MODBUS_FC_MASK_WRITE_REGISTER) {
            length = 6;
        } else if (function == MODBUS_FC_WRITE_AND_READ_REGISTERS) {
            length = 9;
        } else {
            /* MODBUS_FC_READ_EXCEPTION_STATUS, MODBUS_FC_REPORT_SLAVE_ID */
            length = 0;
        }
    } else {
        /* MSG_CONFIRMATION */
        switch (function) {
        case MODBUS_FC_WRITE_SINGLE_COIL:
        case MODBUS_FC_WRITE_SINGLE_REGISTER:
        case MODBUS_FC_WRITE_MULTIPLE_COILS:
        case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:
            length = 4;
            break;
        case MODBUS_FC_MASK_WRITE_REGISTER:
            length = 6;
            break;
        default:
            length = 1;
        }
    }

    return length;
}

/* Computes the length to read after the meta information (address, count, etc) */
static int compute_data_length_after_meta(modbus_t *ctx, uint8_t *msg,
                                          msg_type_t msg_type)
{
    int function = msg[ctx->backend->header_length];
    int length;

    if (msg_type == MSG_INDICATION) {
        switch (function) {
        case MODBUS_FC_WRITE_MULTIPLE_COILS:
        case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:
            length = msg[ctx->backend->header_length + 5];
            break;
        case MODBUS_FC_WRITE_AND_READ_REGISTERS:
            length = msg[ctx->backend->header_length + 9];
            break;
        default:
            length = 0;
        }
    } else {
        /* MSG_CONFIRMATION */
        if (function <= MODBUS_FC_READ_INPUT_REGISTERS ||
            function == MODBUS_FC_REPORT_SLAVE_ID ||
            function == MODBUS_FC_WRITE_AND_READ_REGISTERS) {
            length = msg[ctx->backend->header_length + 1];
        } else {
            length = 0;
        }
    }

    length += ctx->backend->checksum_length;

    return length;
}

///* Waits a response from a modbus server or a request from a modbus client.
//   This function blocks if there is no replies (3 timeouts).
//
//   The function shall return the number of received characters and the received
//   message in an array of uint8_t if successful. Otherwise it shall return -1
//   and errno is set to one of the values defined below:
//   - ECONNRESET
//   - EMBBADDATA
//   - EMBUNKEXC
//   - ETIMEDOUT
//   - read() or recv() error codes
//*/
//
//int _modbus_receive_msg(modbus_t *ctx, uint8_t *msg, msg_type_t msg_type)
//{
//    int rc;
//    fd_set rset;
//    struct timeval tv;
//    struct timeval *p_tv;
//    int length_to_read;
//    int msg_length = 0;
//    _step_t step;
//
//    if (ctx->debug) {
//        if (msg_type == MSG_INDICATION) {
//            printf("Waiting for an indication...\n");
//        } else {
//            printf("Waiting for a confirmation...\n");
//        }
//    }
//
//    /* Add a file descriptor to the set */
//    FD_ZERO(&rset);
//    FD_SET(ctx->s, &rset);
//
//    /* We need to analyse the message step by step.  At the first step, we want
//     * to reach the function code because all packets contain this
//     * information. */
//    step = _STEP_FUNCTION;
//    length_to_read = ctx->backend->header_length + 1;
//
//    if (msg_type == MSG_INDICATION) {
//        /* Wait for a message, we don't know when the message will be
//         * received */
//        if (ctx->indication_timeout.tv_sec == 0 && ctx->indication_timeout.tv_usec == 0) {
//            /* By default, the indication timeout isn't set */
//            p_tv = NULL;
//        } else {
//            /* Wait for an indication (name of a received request by a server, see schema) */
//            tv.tv_sec = ctx->indication_timeout.tv_sec;
//            tv.tv_usec = ctx->indication_timeout.tv_usec;
//            p_tv = &tv;
//        }
//    } else {
//        tv.tv_sec = ctx->response_timeout.tv_sec;
//        tv.tv_usec = ctx->response_timeout.tv_usec;
//        p_tv = &tv;
//    }
//
//    while (length_to_read != 0) {
//        rc = ctx->backend->select(ctx, &rset, p_tv, length_to_read);
//        if (rc == -1) {
//            _error_print(ctx, "select");
//            if (ctx->error_recovery & MODBUS_ERROR_RECOVERY_LINK) {
//                int saved_errno = errno;
//
//                if (errno == ETIMEDOUT) {
//                    _sleep_response_timeout(ctx);
//                    modbus_flush(ctx);
//                } else if (errno == EBADF) {
//                    modbus_close(ctx);
//                    modbus_connect(ctx);
//                }
//                errno = saved_errno;
//            }
//            return -1;
//        }
//
//        rc = ctx->backend->recv(ctx, msg + msg_length, length_to_read);
//        if (rc == 0) {
//            errno = ECONNRESET;
//            rc = -1;
//        }
//
//        if (rc == -1) {
//            _error_print(ctx, "read");
//            if ((ctx->error_recovery & MODBUS_ERROR_RECOVERY_LINK) &&
//                (errno == ECONNRESET || errno == ECONNREFUSED ||
//                 errno == EBADF)) {
//                int saved_errno = errno;
//                modbus_close(ctx);
//                modbus_connect(ctx);
//                /* Could be removed by previous calls */
//                errno = saved_errno;
//            }
//            return -1;
//        }
//
//        /* Display the hex code of each character received */
//        if (ctx->debug) {
//            int i;
//            for (i=0; i < rc; i++)
//                printf("<%.2X>", msg[msg_length + i]);
//        }
//
//        /* Sums bytes received */
//        msg_length += rc;
//        /* Computes remaining bytes */
//        length_to_read -= rc;
//
//        if (length_to_read == 0) {
//            switch (step) {
//            case _STEP_FUNCTION:
//                /* Function code position */
//                length_to_read = compute_meta_length_after_function(
//                    msg[ctx->backend->header_length],
//                    msg_type);
//                if (length_to_read != 0) {
//                    step = _STEP_META;
//                    break;
//                } /* else switches straight to the next step */
//            case _STEP_META:
//                length_to_read = compute_data_length_after_meta(
//                    ctx, msg, msg_type);
//                if ((msg_length + length_to_read) > (int)ctx->backend->max_adu_length) {
//                    errno = EMBBADDATA;
//                    _error_print(ctx, "too many data");
//                    return -1;
//                }
//                step = _STEP_DATA;
//                break;
//            default:
//                break;
//            }
//        }
//
//        if (length_to_read > 0 &&
//            (ctx->byte_timeout.tv_sec > 0 || ctx->byte_timeout.tv_usec > 0)) {
//            /* If there is no character in the buffer, the allowed timeout
//               interval between two consecutive bytes is defined by
//               byte_timeout */
////            tv.tv_sec = ctx->byte_timeout.tv_sec;
////            tv.tv_usec = ctx->byte_timeout.tv_usec;
////            p_tv = &tv;
//			int64_t timeout = ctx->byte_timeout.tv_sec * 1000 *1000 +
//				ctx->byte_timeout.tv_usec;
//			GSource *source = g_main_current_source();
//			fd_source_set_timeout(source,timeout);
//			return TRUE;
//        }
//        /* else timeout isn't set again, the full response must be read before
//           expiration of response timeout (for CONFIRMATION only) */
//    }
//
//    if (ctx->debug)
//        printf("\n");
//	return  ctx->backend->check_integrity(ctx, msg, msg_length);
//}
//

struct _ctx_para{
	modbus_t *ctx;
	modbus_receive_msg_cb cb;
	int msg_type;
	int msg_length;
	int step;
	gpointer data;
	int length_to_read;
//	char *msg;	
	GByteArray *str;
};

static void _ctx_para_destroy(gpointer data){
	g_return_if_fail(data !=NULL);
	struct _ctx_para *para = data;	
	g_byte_array_free(para->str,TRUE);
	g_free(para);	
}


static gboolean _read_msg_cb(modbus_t *ctx,GIOCondition condition,gpointer data){
	struct _ctx_para *para = data;
	gboolean timeout = 0;
	gboolean error = 0;
	if(condition ==0){
		timeout = TRUE;	
		error = TRUE;
		errno = ETIMEDOUT;
	}else if(condition & G_IO_ERROR){
		error = TRUE;
		errno = EBADF;
	}		
	if(error && ctx->error_recovery & MODBUS_ERROR_RECOVERY_LINK){
    	if (errno == ETIMEDOUT) {
    	    _sleep_response_timeout(ctx);
    	    modbus_flush(ctx);
    	} else if (errno == EBADF) {
    	    modbus_close(ctx);
    	    modbus_connect(ctx);
    	}
	}else if(error){
		para->cb(-1,para->str->data,para->str->len,para->data);	
		return FALSE;
	}
	char *buf = g_malloc(para->length_to_read+1);	
	int rc = ctx->backend->recv(para->ctx,buf,para->length_to_read);		
	if(rc == 0){
		errno = ECONNRESET;
		rc = -1;
	}
	if(rc == -1){
        _error_print(ctx, "read");
        if ((ctx->error_recovery & MODBUS_ERROR_RECOVERY_LINK) &&
            (errno == ECONNRESET || errno == ECONNREFUSED ||
             errno == EBADF)) {
            int saved_errno = errno;
            modbus_close(ctx);
            modbus_connect(ctx);
            /* Could be removed by previous calls */
            errno = saved_errno;
        }
		para->cb(-1,para->str->data,para->str->len,para->data);	
		g_free(buf);
        return -1;
	}
    if (ctx->debug) {
        int i;
        for (i=0; i < rc; i++)
            printf("<%.2X>", buf[i]);
    }
	g_byte_array_append(para->str,buf,rc);
	g_free(buf);

	para->msg_length += rc;
	para->length_to_read -=rc;
	if(para->length_to_read ==0){
    	switch (para->step) {
    		case _STEP_FUNCTION:
    		    /* Function code position */
    		    para->length_to_read = compute_meta_length_after_function(
    		        para->str->data[ctx->backend->header_length],
    		        para->msg_type);
    		    if (para->length_to_read != 0) {
    		        para->step = _STEP_META;
    		        break;
    		    } /* else switches straight to the next step */
    		case _STEP_META:
    		    para->length_to_read = compute_data_length_after_meta(
    		        ctx, para->str->data, para->msg_type);
    		    if ((para->msg_length + para->length_to_read) > (int)ctx->backend->max_adu_length) {
    		        errno = EMBBADDATA;
    		        _error_print(ctx, "too many data");
    		        return -1;
    		    }
    		    para->step = _STEP_DATA;
    		    break;
    		default:
    		    break;
   		}

        if (para->length_to_read > 0 &&
            (ctx->byte_timeout.tv_sec > 0 || ctx->byte_timeout.tv_usec > 0)) {
            /* If there is no character in the buffer, the allowed timeout
               interval between two consecutive bytes is defined by
               byte_timeout */
//            tv.tv_sec = ctx->byte_timeout.tv_sec;
//            tv.tv_usec = ctx->byte_timeout.tv_usec;
//            p_tv = &tv;
			int64_t timeout = ctx->byte_timeout.tv_sec * 1000 *1000 +
				ctx->byte_timeout.tv_usec;
			GSource *source = g_main_current_source();
			fd_source_set_timeout(source,timeout);
			return TRUE;
        }
    }
//	}

    if (para->ctx->debug)
        printf("\n");
	int ret  = para->ctx->backend->check_integrity(ctx, para->str->data,para->str->len);
	para->cb(ret,para->str->data,para->str->len,para->data);
    return FALSE;

}

static int _modbus_receive_msg_g(modbus_t *ctx, msg_type_t msg_type,
		modbus_receive_msg_cb cb,gpointer data)
{
    if (ctx->debug) {
        if (msg_type == MSG_INDICATION) {
            printf("Waiting for an indication...\n");
        } else {
            printf("Waiting for a confirmation...\n");
        }
    }
	
	guint64 timout_us = -1;
	struct _ctx_para *para = g_new(struct _ctx_para,1);
	para->ctx = ctx;
	para->cb = cb;
	para->data = data;
	para->length_to_read = ctx->backend->header_length +1;
	para->str = g_byte_array_sized_new(para->length_to_read);
	if(msg_type == MSG_INDICATION){
		if(ctx->indication_timeout.tv_sec !=0 && ctx->indication_timeout.tv_usec !=0)
			timout_us = ctx->indication_timeout.tv_sec *1000 *1000 + 
				ctx->indication_timeout.tv_usec;
	}else{
		timout_us = ctx->response_timeout.tv_sec *1000 *1000
			+ctx->response_timeout.tv_usec;
	}
	if(timout_us <=0) timout_us = -1;

	GSource  *source = fd_source_new(ctx,G_IO_IN |G_IO_ERROR,timout_us);
	g_source_set_callback(source,(GSourceFunc)_read_msg_cb,para,g_free);
	g_source_attach(source,ctx->context);
	g_source_unref(source);
	return 0;
}

/* Computes the length of the expected response */
static unsigned int compute_response_length_from_request(modbus_t *ctx, uint8_t *req)
{
    int length;
    const int offset = ctx->backend->header_length;

    switch (req[offset]) {
    case MODBUS_FC_READ_COILS:
    case MODBUS_FC_READ_DISCRETE_INPUTS: {
        /* Header + nb values (code from write_bits) */
        int nb = (req[offset + 3] << 8) | req[offset + 4];
        length = 2 + (nb / 8) + ((nb % 8) ? 1 : 0);
    }
        break;
    case MODBUS_FC_WRITE_AND_READ_REGISTERS:
    case MODBUS_FC_READ_HOLDING_REGISTERS:
    case MODBUS_FC_READ_INPUT_REGISTERS:
        /* Header + 2 * nb values */
        length = 2 + 2 * (req[offset + 3] << 8 | req[offset + 4]);
        break;
    case MODBUS_FC_READ_EXCEPTION_STATUS:
        length = 3;
        break;
    case MODBUS_FC_REPORT_SLAVE_ID:
        /* The response is device specific (the header provides the
           length) */
        return MSG_LENGTH_UNDEFINED;
    case MODBUS_FC_MASK_WRITE_REGISTER:
        length = 7;
        break;
    default:
        length = 5;
    }

    return offset + length + ctx->backend->checksum_length;
}

static int check_confirmation(modbus_t *ctx, uint8_t *req,
                              uint8_t *rsp, int rsp_length)
{
    int rc;
    int rsp_length_computed;
    const int offset = ctx->backend->header_length;
    const int function = rsp[offset];

    if (ctx->backend->pre_check_confirmation) {
        rc = ctx->backend->pre_check_confirmation(ctx, req, rsp, rsp_length);
        if (rc == -1) {
            if (ctx->error_recovery & MODBUS_ERROR_RECOVERY_PROTOCOL) {
                _sleep_response_timeout(ctx);
                modbus_flush(ctx);
            }
            return -1;
        }
    }

    rsp_length_computed = compute_response_length_from_request(ctx, req);

    /* Exception code */
    if (function >= 0x80) {
        if (rsp_length == (offset + 2 + (int)ctx->backend->checksum_length) &&
            req[offset] == (rsp[offset] - 0x80)) {
            /* Valid exception code received */

            int exception_code = rsp[offset + 1];
            if (exception_code < MODBUS_EXCEPTION_MAX) {
                errno = MODBUS_ENOBASE + exception_code;
            } else {
                errno = EMBBADEXC;
            }
            _error_print(ctx, NULL);
            return -1;
        } else {
            errno = EMBBADEXC;
            _error_print(ctx, NULL);
            return -1;
        }
    }

    /* Check length */
    if ((rsp_length == rsp_length_computed ||
         rsp_length_computed == MSG_LENGTH_UNDEFINED) &&
        function < 0x80) {
        int req_nb_value;
        int rsp_nb_value;

        /* Check function code */
        if (function != req[offset]) {
            if (ctx->debug) {
                fprintf(stderr,
                        "Received function not corresponding to the request (0x%X != 0x%X)\n",
                        function, req[offset]);
            }
            if (ctx->error_recovery & MODBUS_ERROR_RECOVERY_PROTOCOL) {
                _sleep_response_timeout(ctx);
                modbus_flush(ctx);
            }
            errno = EMBBADDATA;
            return -1;
        }

        /* Check the number of values is corresponding to the request */
        switch (function) {
        case MODBUS_FC_READ_COILS:
        case MODBUS_FC_READ_DISCRETE_INPUTS:
            /* Read functions, 8 values in a byte (nb
             * of values in the request and byte count in
             * the response. */
            req_nb_value = (req[offset + 3] << 8) + req[offset + 4];
            req_nb_value = (req_nb_value / 8) + ((req_nb_value % 8) ? 1 : 0);
            rsp_nb_value = rsp[offset + 1];
            break;
        case MODBUS_FC_WRITE_AND_READ_REGISTERS:
        case MODBUS_FC_READ_HOLDING_REGISTERS:
        case MODBUS_FC_READ_INPUT_REGISTERS:
            /* Read functions 1 value = 2 bytes */
            req_nb_value = (req[offset + 3] << 8) + req[offset + 4];
            rsp_nb_value = (rsp[offset + 1] / 2);
            break;
        case MODBUS_FC_WRITE_MULTIPLE_COILS:
        case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:
            /* N Write functions */
            req_nb_value = (req[offset + 3] << 8) + req[offset + 4];
            rsp_nb_value = (rsp[offset + 3] << 8) | rsp[offset + 4];
            break;
        case MODBUS_FC_REPORT_SLAVE_ID:
            /* Report slave ID (bytes received) */
            req_nb_value = rsp_nb_value = rsp[offset + 1];
            break;
        default:
            /* 1 Write functions & others */
            req_nb_value = rsp_nb_value = 1;
        }

        if (req_nb_value == rsp_nb_value) {
            rc = rsp_nb_value;
        } else {
            if (ctx->debug) {
                fprintf(stderr,
                        "Quantity not corresponding to the request (%d != %d)\n",
                        rsp_nb_value, req_nb_value);
            }

            if (ctx->error_recovery & MODBUS_ERROR_RECOVERY_PROTOCOL) {
                _sleep_response_timeout(ctx);
                modbus_flush(ctx);
            }

            errno = EMBBADDATA;
            rc = -1;
        }
    } else {
        if (ctx->debug) {
            fprintf(stderr,
                    "Message length not corresponding to the computed length (%d != %d)\n",
                    rsp_length, rsp_length_computed);
        }
        if (ctx->error_recovery & MODBUS_ERROR_RECOVERY_PROTOCOL) {
            _sleep_response_timeout(ctx);
            modbus_flush(ctx);
        }
        errno = EMBBADDATA;
        rc = -1;
    }

    return rc;
}

static int send_msg(modbus_t *ctx, uint8_t *msg, int msg_length)
{
    int rc;
    int i;

    msg_length = ctx->backend->send_msg_pre(msg, msg_length);

    if (ctx->debug) {
        for (i = 0; i < msg_length; i++)
            printf("[%.2X]", msg[i]);
        printf("\n");
    }

    /* In recovery mode, the write command will be issued until to be
       successful! Disabled by default. */
    do {
        rc = ctx->backend->send(ctx, msg, msg_length);
        if (rc == -1) {
            _error_print(ctx, NULL);
            if (ctx->error_recovery & MODBUS_ERROR_RECOVERY_LINK) {
                int saved_errno = errno;

                if ((errno == EBADF || errno == ECONNRESET || errno == EPIPE)) {
                    modbus_close(ctx);
                    _sleep_response_timeout(ctx);
                    modbus_connect(ctx);
                } else {
                    _sleep_response_timeout(ctx);
                    modbus_flush(ctx);
                }
                errno = saved_errno;
            }
        }
    } while ((ctx->error_recovery & MODBUS_ERROR_RECOVERY_LINK) &&
             rc == -1);

    if (rc > 0 && rc != msg_length) {
        errno = EMBBADDATA;
        return -1;
    }

    return rc;
}


/* Reads the data from a remove device and put that data into an array */
static int read_registers_g(modbus_t *ctx, int function, int addr, int nb,
                          modbus_receive_msg_cb cb,gpointer data)
{
    int rc;
    int req_length;
    uint8_t req[_MIN_REQ_LENGTH];
    uint8_t rsp[MAX_MESSAGE_LENGTH];

    if (nb > MODBUS_MAX_READ_REGISTERS) {
        if (ctx->debug) {
            fprintf(stderr,
                    "ERROR Too many registers requested (%d > %d)\n",
                    nb, MODBUS_MAX_READ_REGISTERS);
        }
        errno = EMBMDATA;
        return -1;
    }

    req_length = ctx->backend->build_request_basis(ctx, function, addr, nb, req);

    rc = send_msg(ctx, req, req_length);
    if (rc > 0) {
        int offset;
        int i;

        rc = _modbus_receive_msg_g(ctx,MSG_CONFIRMATION,cb,data);
    //    if (rc == -1)
    //        return -1;

    //    rc = check_confirmation(ctx, req, rsp, rc);
    //    if (rc == -1)
    //        return -1;

    //    offset = ctx->backend->header_length;

    //    for (i = 0; i < rc; i++) {
    //        /* shift reg hi_byte to temp OR with lo_byte */
    //        dest[i] = (rsp[offset + 2 + (i << 1)] << 8) |
    //            rsp[offset + 3 + (i << 1)];
    //    }
    }

    return rc;
}

/* Reads the holding registers of remote device and put the data into an
   array */
int modbus_read_registers_g(modbus_t *ctx, int addr, int nb,
		modbus_receive_msg_cb cb,gpointer data)
{
    int status;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (nb > MODBUS_MAX_READ_REGISTERS) {
        if (ctx->debug) {
            fprintf(stderr,
                    "ERROR Too many registers requested (%d > %d)\n",
                    nb, MODBUS_MAX_READ_REGISTERS);
        }
        errno = EMBMDATA;
        return -1;
    }

    status = read_registers_g(ctx, MODBUS_FC_READ_HOLDING_REGISTERS,
                            addr, nb, cb,data);
    return status;
}

/* Reads the input registers of remote device and put the data into an array */
//int modbus_read_input_registers_g(modbus_t *ctx, int addr, int nb,
//                                uint16_t *dest)
//{
//    int status;
//
//    if (ctx == NULL) {
//        errno = EINVAL;
//        return -1;
//    }
//
//    if (nb > MODBUS_MAX_READ_REGISTERS) {
//        fprintf(stderr,
//                "ERROR Too many input registers requested (%d > %d)\n",
//                nb, MODBUS_MAX_READ_REGISTERS);
//        errno = EMBMDATA;
//        return -1;
//    }
//
//    status = read_registers(ctx, MODBUS_FC_READ_INPUT_REGISTERS,
//                            addr, nb, dest);
//
//    return status;
//}
