#ifndef MODBUS_EX_H
#define MODBUS_EX_H

#include "modbus.h"

typedef int (*modbus_receive_msg_cb)(modbus_t *ctx,int res,GByteArray *array,void * data);

typedef int (*modbus_read_reg_cb)(modbus_t *ctx,int res,GByteArray *req,GByteArray *rsp,gpointer data);

void modbus_set_context(modbus_t *ctx,GMainContext *context);

GMainContext *modbus_get_context(modbus_t *ctx);

int modbus_read_g(modbus_t *ctx,int function, int addr,int nb,modbus_read_reg_cb cb,gpointer data);

/*
 * modbus 读线圈 	指令字: 0x01
 * */
int modbus_read_bits_g(modbus_t *ctx, int addr, int nb, 
		modbus_read_reg_cb cb,gpointer data);
/*
 * modbus 读输入线圈 指令字: 0x02
 * */
int modbus_read_input_bits_g(modbus_t *ctx, int addr, int nb, 
		modbus_read_reg_cb cb,gpointer data);
/*
 * modbus 读寄存器 	 指令字: 0x03
 * */
int modbus_read_registers_g(modbus_t *ctx, int addr, int nb,
		modbus_read_reg_cb cb,gpointer data);
/*
 * modbus 读输入寄存器 指令字: 0x04
 * */
int modbus_read_input_registers_g(modbus_t *ctx, int addr, int nb,
		modbus_read_reg_cb cb,gpointer data);
/*
 * modbus 写单个线圈 	指令字: 0x05
 * */
int modbus_write_bit_g(modbus_t *ctx, int addr, int status,
		modbus_read_reg_cb cb,gpointer data);
/*
 * modbus 写单个寄存器 	指令字: 0x06
 * */
int modbus_write_register_g(modbus_t *ctx, int addr, uint16_t value,
		modbus_read_reg_cb cb,gpointer data);
/*
 * modbus 写多个线圈 	指令字: 0x0f
 * */
int modbus_write_bits_g(modbus_t *ctx, int addr, int nb, const uint8_t *src,
		modbus_read_reg_cb cb,gpointer data);
/*
 * modbus 写多个寄存器 	指令字: 0x10
 * */
int modbus_write_registers_g(modbus_t *ctx, int addr, int nb, const uint16_t *src,
		modbus_read_reg_cb cb,gpointer data);


uint8_t *modbus_bit_expansion(modbus_t *ctx,uint8_t* rsp,int len);
uint16_t* modbus_reg_expansion(modbus_t *ctx,uint8_t *rsp,int len);
#endif

