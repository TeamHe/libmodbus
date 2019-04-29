#include <glib.h>
#include "../src/modbus.h" 

#define SERVER_ID       17

static int _reg_read_cb(int res,char *buff,int len,gpointer data){

	return 0;
}


int main(int argc,char *argv[]){
	GMainLoop *main_loop = g_main_loop_new(NULL,TRUE);		
	
	modbus_t *ctx = modbus_new_rtu("/dev/ttyUSB0",115200,'N',8,1);
	modbus_set_slave(ctx,1);
	modbus_set_debug(ctx,1);
		
//	uint16_t dest[5] = {0};
	modbus_read_registers_g(ctx,0,3,_reg_read_cb,NULL);
	g_main_loop_run(main_loop);

	g_main_context_unref(g_main_loop_get_context(main_loop));

	g_main_loop_unref(main_loop);
	return 0;
}

