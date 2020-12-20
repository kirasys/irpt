/*
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef IRPT_USER_H
#define IRPT_USER_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#ifndef __MINGW64__
#include <sys/mman.h>
#endif

#include <stdint.h>

#define HYPERCALL_IRPT_RAX_ID				0x01f
#define HYPERCALL_IRPT_ACQUIRE				0
#define HYPERCALL_IRPT_GET_PAYLOAD			1
#define HYPERCALL_IRPT_GET_PROGRAM			2
#define HYPERCALL_IRPT_GET_ARGV				3
#define HYPERCALL_IRPT_RELEASE				4
#define HYPERCALL_IRPT_SUBMIT_CR3			5
#define HYPERCALL_IRPT_SUBMIT_PANIC			6
#define HYPERCALL_IRPT_SUBMIT_KASAN			7
#define HYPERCALL_IRPT_PANIC				8
#define HYPERCALL_IRPT_KASAN				9
#define HYPERCALL_IRPT_SNAPSHOT				10
#define HYPERCALL_IRPT_INFO					11
#define HYPERCALL_IRPT_NEXT_PAYLOAD			12
#define HYPERCALL_IRPT_PRINTF				13
#define HYPERCALL_IRPT_PRINTK_ADDR			14
#define HYPERCALL_IRPT_PRINTK				15

/* user space only hypercalls */
#define HYPERCALL_IRPT_USER_RANGE_ADVISE	16
#define HYPERCALL_IRPT_USER_SUBMIT_MODE		17
#define HYPERCALL_IRPT_USER_FAST_ACQUIRE	18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_IRPT_USER_ABORT			20
#define HYPERCALL_IRPT_TIMEOUT				21

/* kirasys */
#define HYPERCALL_IRPT_LOCK					22
#define HYPERCALL_IRPT_IP_FILTER			23
#define HYPERCALL_IRPT_MEMWRITE				24

#define PAYLOAD_SIZE						0x10000					
#define PROGRAM_SIZE						(128 << 20)				/* IRPT supports 128MB programm data */
#define INFO_SIZE        					(128 << 10)				/* 128KB info string */
#define TARGET_FILE							"/tmp/fuzzing_engine"	/* default target for the userspace component */
#define TARGET_FILE_WIN						"fuzzing_engine.exe"	

#define HPRINTF_MAX_SIZE					0x1000					/* up to 4KB hprintf strings */

/* agent action */
#define EXECUTE_IRP			0
#define DRIVER_REVERT 		1
#define DRIVER_RELOAD		2
#define SCAN_PAGE_FAULT		3
#define ANTI_IOCTL_FILTER	4

typedef struct{
	uint32_t Command;
	uint32_t IoControlCode;
	uint32_t InBufferLength;
	uint32_t OutBufferLength;
	uint8_t InBuffer[PAYLOAD_SIZE];
} IRPT_payload;

#if defined(__i386__)
static void Hypercall(uint32_t rbx, uint32_t rcx){
	printf("%s %x %x \n", __func__, rbx, rcx);
	uint32_t rax = HYPERCALL_IRPT_RAX_ID;
    asm volatile("movl %0, %%ecx;"
				 "movl %1, %%ebx;"  
				 "movl %2, %%eax;"
				 "vmcall" 
				: 
				: "r" (rcx), "r" (rbx), "r" (rax) 
				: "eax", "ecx", "ebx"
				);
} 
#elif defined(__x86_64__)

static void Hypercall(uint64_t rbx, uint64_t rcx){
	uint64_t rax = HYPERCALL_IRPT_RAX_ID;
    asm volatile("movq %0, %%rcx;"
				 "movq %1, %%rbx;"  
				 "movq %2, %%rax;"
				 "vmcall" 
				: 
				: "r" (rcx), "r" (rbx), "r" (rax)
				: "rax", "rcx", "rbx"
				);
}

static void HypercallEx(uint64_t rbx, uint64_t rcx, uint64_t rdx, uint64_t rsi){
	uint64_t rax = HYPERCALL_IRPT_RAX_ID;
    asm volatile("movq %0, %%rsi;"
				 "movq %1, %%rdx;"
				 "movq %2, %%rcx;"
				 "movq %3, %%rbx;"  
				 "movq %4, %%rax;"
				 "vmcall" 
				: 
				: "r" (rsi), "r" (rdx), "r" (rcx), "r" (rbx), "r" (rax) 
				: "rax", "rcx", "rbx", "rdx", "rsi"
				);
}
#endif

uint8_t* hprintf_buffer = NULL; 

static inline uint8_t alloc_hprintf_buffer(void){
	if(!hprintf_buffer){
#ifdef __MINGW64__
		hprintf_buffer = (uint8_t*)VirtualAlloc(0, HPRINTF_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);
#else 
		hprintf_buffer = mmap((void*)NULL, HPRINTF_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
		if(!hprintf_buffer){
			return 0;
		}
	}
	return 1; 
}

static void hprintf(const char * format, ...)  __attribute__ ((unused));

static void hprintf(const char * format, ...){
	va_list args;
	va_start(args, format);
	if(alloc_hprintf_buffer()){
		vsnprintf((char*)hprintf_buffer, HPRINTF_MAX_SIZE, format, args);
# if defined(__i386__)
		printf("%s", hprintf_buffer);
		Hypercall(HYPERCALL_IRPT_PRINTF, (uint32_t)hprintf_buffer);
# elif defined(__x86_64__)
		printf("%s", hprintf_buffer);
		Hypercall(HYPERCALL_IRPT_PRINTF, (uint64_t)hprintf_buffer);
# endif
	}
	//vprintf(format, args);
	va_end(args);
}
#endif
