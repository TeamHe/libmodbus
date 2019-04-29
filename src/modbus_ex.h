#ifndef MODBUS_EX_H
#define MODBUS_EX_H

#include "modbus.h"

typedef int (*modbus_receive_msg_cb)(modbus_t *ctx,int res,GByteArray *array,void * data);

typedef int (*modbus_read_reg_cb)(modbus_t *ctx,int res,GByteArray *req,GByteArray *rsp,gpointer data);

int modbus_read_registers_g(modbus_t *ctx, int addr, int nb,
		modbus_read_reg_cb cb,gpointer data);
void modbus_set_context(modbus_t *ctx,GMainContext *context);

GMainContext *modbus_get_context(modbus_t *ctx);

#endif

