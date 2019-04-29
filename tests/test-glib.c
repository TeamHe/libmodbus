#include "../src/modbus_ex.h" 
#include <stdio.h>

#define SERVER_ID       17


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
	modbus_free(ctx);
	g_main_loop_quit(data);
//	g_timer_stop(timer);
	return 0;
}

static gboolean _time_on(gpointer data)
{

}

static void test_normal(){
	GTimer *timer = g_timer_new();
	g_timer_start(timer);
	modbus_t *ctx = modbus_new_tcp("192.168.2.4",502);
	modbus_set_slave(ctx,1);
	modbus_set_debug(ctx,1);
	modbus_set_response_timeout(ctx,2,0);
	
	if(modbus_connect(ctx)<0){
		printf("connect fail\n");
	}
//	uint16_t dest[5] = {0};
	uint16_t buff[5] = {0};
	modbus_read_registers(ctx,0,3,buff);
//	modbus_read_registers_g(ctx,0,3,_reg_read_cb,);
	gdouble time = g_timer_elapsed(timer,NULL);
	printf("normal time:%lf s\n",time);
	modbus_free(ctx);
	g_timer_destroy(timer);
}

int main(int argc,char *argv[]){
	test_normal();
	GTimer *timer = g_timer_new();
	g_timer_start(timer);
	GMainLoop *main_loop = g_main_loop_new(NULL,TRUE);		
	
//	modbus_t *ctx = modbus_new_rtu("/dev/ttyUSB0",115200,'N',8,1);
	modbus_t *ctx = modbus_new_tcp("192.168.2.4",502);
	modbus_set_slave(ctx,1);
	modbus_set_debug(ctx,1);
	modbus_set_response_timeout(ctx,2,0);
	
	if(modbus_connect(ctx)<0){
		printf("connect fail\n");
		return 0;
	}
//	uint16_t dest[5] = {0};
	modbus_read_registers_g(ctx,0,3,_reg_read_cb,main_loop);
	g_main_loop_run(main_loop);

	g_main_context_unref(g_main_loop_get_context(main_loop));

	g_main_loop_unref(main_loop);
	gdouble time = g_timer_elapsed(timer,NULL);
	printf("time:%lf s\n",time);
	g_timer_destroy(timer);
	return 0;
}

