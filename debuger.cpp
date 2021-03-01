/*
利用ptrace来跟踪，继续执行，读取和写入内存
PTRACE_ATTACHME
PTRACE_CONT
PTRACE_PEEKDATA 读取
PTRACE_POKEDATA 写入
PTRACE_GETREGS 获得寄存器值
PTRACE_SETREGS 写入寄存器值
PTRACE_SINGLESTEP

并搭配waitpid()，收到信号后，唤醒debuger
64位下word是64位
static_cast()四种类型转换
stol()将str转换为数字
*/


#include <iostream>
#include <vector>
#include <unordered_map>
#include <sys/personality.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sstream>

#include <algorithm>
#include <sys/user.h>
#include <iomanip>

#include "linenoise/linenoise.h"

using namespace std;

enum class reg{
	rax,rbx,rcx,rdx,
	rdi,rsi,rbp,rsp,
	r8,r9,r10,r11,
	r12,r13,r14,r15,
	rip,rflags,cs,
	orig_rax,fs_base,
	gs_base,
	fs,gs,ss,ds,es
};

constexpr std::size_t n_registers=27;

struct reg_descriptor
{
	reg r;
	int dwarf_r;
	std::string name;
};

const array<reg_descriptor,n_registers> g_register_descriptors{{
	{ reg::r15,15,"r15"},
	{ reg::r14,14,"r14"},
	{ reg::r13, 13, "r13" },
    { reg::r12, 12, "r12" },
    { reg::rbp, 6, "rbp" },
    { reg::rbx, 3, "rbx" },
    { reg::r11, 11, "r11" },
    { reg::r10, 10, "r10" },
    { reg::r9, 9, "r9" },
    { reg::r8, 8, "r8" },
    { reg::rax, 0, "rax" },
    { reg::rcx, 2, "rcx" },
    { reg::rdx, 1, "rdx" },
    { reg::rsi, 4, "rsi" },
    { reg::rdi, 5, "rdi" },
    { reg::orig_rax, -1, "orig_rax" },
    { reg::rip, -1, "rip" },
    { reg::cs, 51, "cs" },
    { reg::rflags, 49, "eflags" },
    { reg::rsp, 7, "rsp" },
    { reg::ss, 52, "ss" },
    { reg::fs_base, 58, "fs_base" },
    { reg::gs_base, 59, "gs_base" },
    { reg::ds, 53, "ds" },
    { reg::es, 50, "es" },
    { reg::fs, 54, "fs" },
    { reg::gs, 55, "gs" },
}};

uint64_t get_register_value(pid_t pid, reg r)
{
	user_regs_struct regs;
	ptrace(PTRACE_GETREGS,pid,nullptr,&regs);

	//lambda()匿名函数，[]捕获外部变量，()形参列表，g_register_descriptors与r比较，因为传进来的是r，然后des与regs结构相同，可以查找
	auto it=find_if(begin(g_register_descriptors),end(g_register_descriptors),
	[r](auto&& rd) {return rd.r==r;});

	//re...cast类型转换，地址相减，取内容，获得寄存器值
	return *(reinterpret_cast<uint64_t*>(&regs)+(it-begin(g_register_descriptors)));
}

void set_register_value(pid_t pid,reg r,uint64_t value)
{
	user_regs_struct regs;
	ptrace(PTRACE_GETREGS,pid, nullptr, &regs);
	auto it=find_if(begin(g_register_descriptors),end(g_register_descriptors),
	[r](auto&& rd){return rd.r==r;});

	*(reinterpret_cast<uint64_t*>(&regs)+(it-begin(g_register_descriptors)))=value;
	ptrace(PTRACE_SETREGS,pid,nullptr,&regs);
}

uint64_t get_register_value_from_dwarf_register(pid_t pid,unsigned regnum)
{
	auto it = find_if(begin(g_register_descriptors),end(g_register_descriptors),
	[regnum](auto&& rd){return rd.dwarf_r==regnum;});
	if (it==end(g_register_descriptors))
	{
		throw out_of_range{"Unknown dwarf register!"};
	}
	return get_register_value(pid,it->r);	
}

string get_register_name(reg r)
{
	auto it =find_if(begin(g_register_descriptors),end(g_register_descriptors),
	[r](auto&& rd){return rd.r==r;});

	return it->name;
}

reg get_register_from_name(const string& name)
{
	auto it=find_if(begin(g_register_descriptors),end(g_register_descriptors),
	[name](auto&& rd){return rd.name==name;});

	return it->r;
}

void error(string s)
{
	cerr<<s<<" failed!\n";
	cerr<<strerror(errno);
}

vector<string> split(const string &s,char delimiter)
{
	vector<string> out{};
	stringstream ss{s};
	string item;

	while (getline(ss,item,delimiter))
	{
		out.push_back(item);
	}
	
	return out;
}

bool is_prefix(const string& s,const string& of)
{
	if (s.size()>of.size())
	{
		return false;
	}
	return equal(s.begin(),s.end(),of.begin());
}

class breakpoint 
{
	public:
		//初始化将花括号改为圆括号一样可以
		breakpoint(pid_t pid,intptr_t addr)
			:m_pid(pid),m_addr{addr},m_enabled{false},m_saved_data{}
		{}

		//遇到错误/usr/include/c++/10/tuple:1689:70: error: 
		//no matching function for call to ‘breakpoint::breakpoint()’
		breakpoint(){}

		void enable();
		void disable();

		auto is_enabled() const->bool {return m_enabled;}
		auto get_address() const-> intptr_t{return m_addr;}


	private:
		pid_t m_pid;
		intptr_t m_addr;
		bool m_enabled;
		uint8_t m_saved_data;

};

void breakpoint::enable()
{
	//peekdata返回进程该地址处的word数据，即64位
	auto data=ptrace(PTRACE_PEEKDATA,m_pid,m_addr,nullptr);
	//static_cast四种类型转换之一，xxx_cast<newType>(data)
	//newType想要转成的类型，data转换数据

	//小端序，数据低位放在小地址处，所以该地址的数据是读出来数据的低位
	m_saved_data=static_cast<uint8_t>(data & 0xff);
	uint64_t int3=0xcc;
	uint64_t data_with_int3=((data & ~0xff) | int3); //设置断点地址指令为0xcc

	//PTRACE_POKEDATA写数据，word64位
	ptrace(PTRACE_POKEDATA,m_pid,m_addr,data_with_int3);

	m_enabled=true;
}

void breakpoint::disable()
{
	auto data=ptrace(PTRACE_PEEKDATA,m_pid,m_addr,nullptr);
	auto restored_data=((data & ~0xff) | m_saved_data);
	ptrace(PTRACE_POKEDATA,m_pid,m_addr,restored_data);

	m_enabled=false;
}


class debuger
{
private:
	string m_prog_name;
	pid_t m_pid;
	unordered_map<intptr_t,breakpoint> m_breakpoints;
public:
	debuger(string , pid_t);
	~debuger();
	void run();
	void handle_command(const string &);
	void continue_execution();
	void set_breakpoint_at_address(intptr_t addr);
	void dump_registers();
	uint64_t read_memory(uint64_t address);
	void write_memory(uint64_t address,uint64_t value);
	uint64_t get_pc();
	void set_pc(uint64_t);
	void step_over_breakpoint();
	void wait_for_signal();
};

debuger::debuger(string prog_name, pid_t pid):m_prog_name{move(prog_name)},m_pid{pid}{}

debuger::~debuger(){}

void debuger::run()
{
	int wait_status;
	auto options=0;
	//PTRACE_TRACEME：表示此进程将被父进程跟踪，任何信号（除了 SIGKILL）都会暂停子进程，接着阻塞于 wait() 等待的父进程被唤醒。

	/*如果在调用waitpid()函数时，当指定等待的子进程已经停止运行或结束了，则waitpid()会立即返回；
	但是如果子进程还没有停止运行或结束，则调用waitpid()函数的父进程则会被阻塞，暂停运行。*/
	waitpid(m_pid,&wait_status,options);

	char* line=nullptr;
	while ((line = linenoise("minidbg> "))!=nullptr)
	{
		handle_command(line);
		linenoiseHistoryAdd(line); //加入linenoise历史
		linenoiseFree(line);
	}
	
}

void debuger::handle_command(const string & line)
{
	auto args=split(line ,' ');
	auto command =args[0];

	if (is_prefix(command, "continue"))
	{
		continue_execution();
	}
	else if (is_prefix(command,"break"))
	{ 
		//string addr(args[1],2);从第二个位置开始读取
		string addr(args[1]); //天真地相信用户输入
		//stol将str转换为数字，
		//(const string&  str, size_t* idx = 0, int base = 10);
		set_breakpoint_at_address(stol(addr,0,16));
	}
	else if (is_prefix(command,"register"))
	{
		if (is_prefix(args[1],"dump"))
		{
			dump_registers();
		}
		else if (is_prefix(args[1],"read"))
		{
			cout<<get_register_value(m_pid,get_register_from_name(args[2]))<<endl;
		}
		else if (is_prefix(args[1],"write"))
		{
			string val(args[3],2);
			set_register_value(m_pid,get_register_from_name(args[2]),stol(val,0,16));
		}
	}
	else if (is_prefix(command,"memory"))
	{
		string addr{args[2],2}; //assume 0xaddress

		if (is_prefix(args[1],"read"))
		{
			cout<<hex<<read_memory(stol(addr,0,16))<<endl;
		}
		if (is_prefix(args[1],"write"))
		{/* condition */
			string val{args[3],2};
			write_memory(stol(addr,0,16),stol(val,0,16));
		}	
	}
	else
	{
		cerr<<"Unknown command\n";
	}
}

void debuger::continue_execution()
{
	step_over_breakpoint();
	ptrace(PTRACE_CONT,m_pid,nullptr,nullptr);
	wait_for_signal();
}

void debuger::set_breakpoint_at_address(intptr_t addr)
{
	cout<<"Set breakpoint at address 0x"<<hex<<addr<<endl;
	breakpoint bp{m_pid,addr};
	bp.enable();
	//m_breakpoints[addr]=bp;
	//my version
	m_breakpoints.insert(make_pair(addr,bp));
}

void debuger::dump_registers()
{
	for (const auto& rd : g_register_descriptors) //c++11 中带入
	{
		cout<<rd.name<<" 0x"
		<<setfill('0')<<setw(16)<<hex<<get_register_value(m_pid,rd.r)<<endl;
		//设置std::setw将填充什么样的字符，如:std::setfill('*')
	}
	
}

uint64_t debuger::read_memory(uint64_t address)
{
	return ptrace(PTRACE_PEEKDATA,m_pid,address,nullptr);
}

void debuger::write_memory(uint64_t address,uint64_t value)
{
	ptrace(PTRACE_POKEDATA,m_pid,address,value);
}

void debuger::step_over_breakpoint()
{
	//rip 此时为断点值加一
	auto possible_breakpoint_location = get_pc()-1;
	if (m_breakpoints.count(possible_breakpoint_location))
	{
		auto& bp=m_breakpoints[possible_breakpoint_location];

		if (bp.is_enabled())
		{
			auto previous_instruction_address =possible_breakpoint_location;
			set_pc(previous_instruction_address);

			bp.disable();
			ptrace(PTRACE_SINGLESTEP,m_pid,nullptr,nullptr);
			wait_for_signal();
			bp.enable();
		}	
	}
}

uint64_t debuger::get_pc()
{
	return get_register_value(m_pid,reg::rip);
}

void debuger::set_pc(uint64_t pc)
{
	set_register_value(m_pid,reg::rip,pc);
}

void debuger::wait_for_signal()
{
	int wait_status;
	auto options=0;
	waitpid(m_pid,&wait_status,options);
}

int main(int argc, char *argv[])
{

	if (argc < 2)
	{
		cerr << "Program name not specified\n";
		return -1;
	}

	auto prog = argv[1];

	auto pid = fork(); //fork 一个新的进程，并返回pid

	if (pid == 0)
	{
		//in child
		//PTRACE_TRACEME
        //      Indicate that this process is to be traced by its parent
		if(ptrace(PTRACE_TRACEME,0,nullptr,nullptr)==-1)
		{
			error("ptrace");
			return -1;
		}

		//execl()用来执行参数path 字符串所代表的文件路径, 接下来的参数代表执行该文件时传递过去的argv(0), argv[1], ..., 
		//最后一个参数必须用空指针(NULL)作结束. argv(0)就是程序本身的名字
		/*
		PTRACE_TRACEME：表示此进程将被父进程跟踪，任何信号（除了 SIGKILL）都会暂停子进程，接着阻塞于 wait() 等待的父进程被唤醒。
		子进程内部对 exec() 的调用将发出 SIGTRAP 信号，这可以让父进程在子进程新程序开始运行之前就完全控制它。
		*/
		personality(ADDR_NO_RANDOMIZE);//提供运行空间，关闭ASLR https://man7.org/linux/man-pages/man2/personality.2.html
		execl(prog,prog,nullptr);
	}
	else if (pid>=1)
	{
		//in parent
		cout<<"Started debugging process "<< pid <<  "\n";
		//初始化，int units_sold = 0;int units_sold = {0};int units_sold{0};int units_sold(0);
		//不用'='的两种方法,新标准中引用,c++11
		//debuger dbg{prog,pid}; 
		debuger dbg(prog,pid);
		dbg.run();
	}
	
}
