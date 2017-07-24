#include <log.h>

const int log_level=log_debug;

char log_text[][10]={"FATAL","ERROR","WARN","INFO","DEBUG","TRACE"};
char log_color[][10]={RED,RED,YEL,GRN,BLU,""};
void log(int level,const char* str, ...) {

	if(level>log_level) return ;
	if(level>log_trace||level<0) return ;


	time_t timer;
	char buffer[100];
	struct tm* tm_info;

	time(&timer);
	tm_info = localtime(&timer);

	printf(log_color[level]);

	strftime(buffer, 100, "%Y-%m-%d %H:%M:%S", tm_info);
	printf("[%s][%s]",buffer,log_text[level]);


	va_list vlist;
	va_start(vlist, str);
	vfprintf(stdout, str, vlist);
	va_end(vlist);
	printf(RESET);
	//printf("\n");
	fflush(stdout);
}
