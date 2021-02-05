#$@:表示目标文件
#$^:表示所有依赖文件
#$<:表示第一个依赖文件


objects=debuger.o linenoise.o
 
all:$(objects)
	g++ -o my_debuger $(objects)
 
debuger.o:debuger.cpp linenoise.h
	g++ -g -o $@ -c $< 
 
linenoise.o:linenoise.c linenoise.h
	gcc -g -o $@ -c $< 
 
clean:
	rm -rf $(objects) my_debuger
