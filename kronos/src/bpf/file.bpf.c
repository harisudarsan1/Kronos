
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// char LICENSE[] SEC("license") = "GPL";
#define MAX_FILE_SIZE 255

SEC("kprobe/cap_capable")
int BPF_KPROBE(kprobe__cap_capable, const struct cred *cred,
               struct user_namespace *targ_ns, int cap, int cap_opt) {
  return 0;
}

SEC("lsm/file_open")
int BPF_PROG(test_prog, struct file *file, int ret)
{
	// struct task_struct *ts;
	char path_buffer[MAX_FILE_SIZE];
	// long err = bpf_d_path(&file->f_path, path_buffer, sizeof(path_buffer));

	bpf_printk("we got full path %s", path_buffer);
	// // ts = bpf_get_current_task_btf();
	// struct task_struct *task = (void *)bpf_get_current_task();
	// // int tgid = BPF_CORE_READ(task, tgid);
	// struct file *exe_file;
	// BPF_CORE_READ_INTO(&exe_file, task, mm, exe_file);
	// if (!exe_file)
	// 	return 0; // Skip if exe_file is NULL
	//
	// // long err2 = bpf_d_path(&exe_file->f_path, path_buffer, sizeof(path_buffer));
	//
	// long err2 = bpf_path_d_path(&exe_file->f_path, path_buffer, sizeof(path_buffer));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
