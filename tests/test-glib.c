#include "../src/modbus_ex.h" 
#include <stdio.h>

#define SERVER_ID       17

#define FUNC 			0x05
#define START 			0X00
#define LEN 			0x03

static int _reg_read_cb(modbus_t *ctx,int res,GByteArray *req,GByteArray *rsp,gpointer data){
	printf("modbus req res:%d\n",res);
	printf("array req:");
	for(int i=0;i<req->len;i++){
		printf("%02X ",req->data[i]);
	}
	printf("\narray rsp:");
	for(int i=0;i<rsp->len;i++){
		printf("%02X ",rsp->data[i]);
	}
	printf("\n");
	if(res > 0){
		switch(FUNC){
			case MODBUS_FC_READ_HOLDING_REGISTERS:
			case MODBUS_FC_READ_INPUT_REGISTERS:
				{
					uint16_t *reg = modbus_reg_expansion(ctx,rsp->data,res);
					printf("read reg func %d len:%d:\n",FUNC,res);
					for(int i=0;i<res;i++){
						printf("%-5d ",reg[i]);
					}
					printf("\n");
					g_free(reg);
				}
				break;
			case MODBUS_FC_READ_COILS:
			case MODBUS_FC_READ_DISCRETE_INPUTS:
				{
					uint8_t *reg = modbus_bit_expansion(ctx,rsp->data,LEN);
					printf("read reg func %d len:%d:",FUNC,LEN);
					for(int i=0;i<LEN;i++){
						printf("%s ",reg[i]==TRUE?"TRUE":"FALSE");
					}
					printf("\n");
					g_free(reg);
				}
				break;
		}		
	}
	modbus_free(ctx);
	g_main_loop_quit(data);
	return 0;
}


int main(int argc,char *argv[]){
//	test_normal();
	GTimer *timer = g_timer_new();
	g_timer_start(timer);
	GMainLoop *main_loop = g_main_loop_new(NULL,TRUE);		
	
//	modbus_t *ctx = modbus_new_rtu("/dev/ttyUSB0",115200,'N',8,1);
	modbus_t *ctx = modbus_new_tcp("192.168.2.4",502);
	modbus_set_slave(ctx,1);
	modbus_set_debug(ctx,1);
//	modbus_set_context(ctx,NULL);
	modbus_set_response_timeout(ctx,2,0);
	
	if(modbus_connect(ctx)<0){
		printf("connect fail\n");
		return 0;
	}
		
//	modbus_read_g(ctx,FUNC,START,LEN,_reg_read_cb,main_loop);
//	modbus_read_bits_g(ctx,0,3,_reg_read_cb,main_loop);
//	modbus_write_bit_g(ctx,2,0xff,_reg_read_cb,main_loop);
	uint8_t data[] = {0x01,0x01,0x01};
	uint16_t reg[] = {34,56,78};
	modbus_write_registers_g(ctx,0x04,0x03,reg,_reg_read_cb,main_loop);
	g_main_loop_run(main_loop);

	g_main_context_unref(g_main_loop_get_context(main_loop));

	g_main_loop_unref(main_loop);
	gdouble time = g_timer_elapsed(timer,NULL);
	printf("time:%lf s\n",time);
	g_timer_destroy(timer);
	return 0;
}

