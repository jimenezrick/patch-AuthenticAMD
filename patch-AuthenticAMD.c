/* Copyright (C) 2008-2011 Ricardo Catalinas Jiménez <jimenezrick@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------
 * --- Uncripple Intel binaries for AMD processors ---
 * ---------------------------------------------------
 *
 * It removes the `cmp/cmpl' instructions near a `cpuid' one used to test
 * the vendor string of the CPU. Works on ELF binaries and shared libraries.
 *
 * Tested with Intel C++ Compiler 10.x and 11.x. It might also work with
 * next versions of the compiler.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <gelf.h>

#define PRINT_ERROR_MESSAGE(message, print_help_message) print_error_message(__LINE__, message, print_help_message)
#define PRINT_ERRNO() print_errno(__LINE__)
#define PRINT_ELF_ERRNO() print_elf_errno(__LINE__)

/* The compiler always uses a CPUID instruction before the string comparison. */
#define CPUID_BYTES_DISTANCE 200

/* The instruction used to test the CPU string depends on the version of the compiler:
 * - Until ICC 10.x the instruction was `cmp $value,%eax' with opcode `0x3d, value'.
 * - From ICC 11.x and onwards the instruction is `cmpl $value,disp(%rbp)' with opcode
 *   `0x81, 0x7d, disp, value'.
 */
#define CMP_OPCODE   0x3d
#define CMPL_OPCODE1 0x81
#define CMPL_OPCODE2 0x7d

char *PROGRAM_NAME;

struct {
	bool verbose;
	bool analyze_elf;
	bool read_only;
	bool replace_complete_string;
	bool patch_all_sections;
	char *vendor_string;
	int cpuid_bytes_distance;
} options;

void print_help(void)
{
	printf("Usage: patch-AuthenticAMD [-e] [-c] [-d <bytes_distance>] [-a] [-r] [-s <vendor_string>] [-v] <executable_to_patch> | -h\n\n"
			"The vendor string must be 12 characters long. The executable to patch must be an\n"
			"ELF program or an ELF share library.\n\n"
			"-e: don't analyze the ELF structure, just do the substitutions in all the binary\n"
			"\tfile. By default the substitutions are done only in executable sections of the binary.\n"
			"-c: don't replace the complete vendor string, just any partial occurrence of it.\n"
			"-d: set the max number of bytes between a CPUID instruction and a substitution.\n"
			"\tThe default value is %i. A zero value disables this check.\n"
			"-a: patch all sections of the ELF executable, even if these sections aren't\n"
			"\tmachine code. By default only patch executable sections.\n"
			"-r: work on read-only mode. Try to use in conjunction with the \"-v\" option.\n"
			"-s: set the vendor string. The default is \"AuthenticAMD\".\n"
			"-v: give verbose output.\n"
			"-h: print this help.\n", CPUID_BYTES_DISTANCE);
}

void print_error_message(int line_number, char *message, bool print_help_message)
{
	fprintf(stderr, "%s (line %i): %s\n", PROGRAM_NAME, line_number, message);
	if (print_help_message)
		print_help();
	exit(1);
}

void print_errno(int line_number)
{
	char str[100];

	snprintf(str, 100, "%s (line %i)", PROGRAM_NAME, line_number);
	perror(str);
	exit(2);
}

void print_elf_errno(int line_number)
{
	int err;

	if ((err = elf_errno()) != 0) {
		fprintf(stderr, "%s (line %i): %s\n", PROGRAM_NAME, line_number, elf_errmsg(err));
		exit(3);
	}
}

/* `start_address' contains NULL when called with `mmap', so we can calculate the address
 * in the file of the interesting byte. But when called with `libelf', `start_address'
 * has each time is called the real start address of the section in the executable
 * when this is loaded to memory by the operating system.
 */
int replace_vendor_string(unsigned char *data, int data_size, unsigned char *start_address)
{
	char replace_words[3][4], search_words[3][4] = {"Genu", "ineI" ,"ntel"};
	int substitutions = 0, next_word = 0, last_substitution = 0;
	int cpuid_occurrence = -1, i, j;

	for (j = 0, i = 0; j < 3 && i < 12; j++, i += 4)
		memcpy(replace_words[j], options.vendor_string + i, 4);

	for (i = 0; i < data_size; i++) {
		if (data[i] == 0x0f && i < data_size - 1 && data[i + 1] == 0xa2) {
			cpuid_occurrence = i;
			if (options.verbose)
				printf("\t---> CPUID instruction found at %p\n", start_address + i);
			i++;
		}

		if ((i < data_size - 4 && data[i] == CMP_OPCODE) ||                                              /* ICC <= 10.x */
				(i < data_size - 7 && data[i] == CMPL_OPCODE1 && data[i + 1] == CMPL_OPCODE2)) { /* ICC >= 11.x */
			i += (data[i] == CMP_OPCODE) ? 1 : 3;
			for (j = 0; j < 3; j++) {
				if (!memcmp(data + i, search_words[j], 4)) {
					if ((options.replace_complete_string && j == next_word) ||
							!options.replace_complete_string) {
						if (!options.read_only) {
							if (options.cpuid_bytes_distance == 0 || (cpuid_occurrence != -1 &&
										i - cpuid_occurrence <= options.cpuid_bytes_distance)) {
								memcpy(data + i, replace_words[j], 4);
								last_substitution = i;
							} else {
								printf("\t---> Warning: possible substitution at %p but not CPUID\n"
										"\t\tinstruction near it, so not replaced\n",
										start_address + i);
								break;
							}
						}

						if (options.replace_complete_string && next_word == 2) {
							substitutions++;
							if (options.verbose)
								printf("\t===> Complete substitution at %p\n",
										start_address + i);
						} else if (!options.replace_complete_string) {
							substitutions++;
							if (options.verbose)
								printf("\t===> Partial substitution at %p\n",
										start_address + i);
						}
						next_word = (1 + next_word) % 3;
						i += 4;
						break;
					} else {
						printf("\t---> Warning: partial substitution at %p, but not replaced\n",
								start_address + i);
						break;
					}
				}
			}
		}
	}

	if (options.replace_complete_string && next_word != 0) {
		printf("\t---> Warning: last complete substitution at %p was partially made\n",
				start_address + last_substitution);
		if (!options.read_only)
			printf("\t\t(no changes will be written in this data block)\n");
	}

	return substitutions;
}

int analyze_elf_binary(int file_descriptor, unsigned char *file_data)
{
	Elf *elf_handle;
	GElf_Ehdr elf_executable_header;
	Elf_Scn *section;
	GElf_Shdr section_header;
	char *section_name;
	int replacements;

	if (elf_version(EV_CURRENT) == EV_NONE)
		PRINT_ELF_ERRNO();
	if ((elf_handle = elf_begin(file_descriptor, ELF_C_READ, NULL)) == NULL)
		PRINT_ELF_ERRNO();
	if (gelf_getehdr(elf_handle, &elf_executable_header) == NULL)
		PRINT_ELF_ERRNO();

	switch(elf_kind(elf_handle)) {
		case ELF_K_NUM:
		case ELF_K_NONE:
			PRINT_ERROR_MESSAGE("file type unknown", false);
			break;
		case ELF_K_COFF:
			PRINT_ERROR_MESSAGE("COFF binaries not supported", false);
			break;
		case ELF_K_AR:
			PRINT_ERROR_MESSAGE("AR archives not supported", false);
			break;
		case ELF_K_ELF:
			if (options.verbose) {
				if (gelf_getclass(elf_handle) == ELFCLASS32)
					printf("Reading 32-bit ELF binary");
				else
					printf("Reading 64-bit ELF binary");

				if (options.read_only)
					printf(" in read-only mode\n");
				else
					printf("\n");
			}
			break;
	}

	replacements = 0;
	section = NULL;
	while ((section = elf_nextscn(elf_handle, section)) != NULL) {
		if (gelf_getshdr(section, &section_header) != &section_header)
			PRINT_ELF_ERRNO();

		if ((section_name = elf_strptr(elf_handle, elf_executable_header.e_shstrndx,
						section_header.sh_name)) == NULL)
			PRINT_ELF_ERRNO();

		if (options.verbose && !(section_header.sh_flags & SHF_EXECINSTR))
			printf("* Section %s\n", section_name);
		else if (options.verbose)
			printf("* Section %s is executable\n", section_name);

		if (section_header.sh_flags & SHF_EXECINSTR || options.patch_all_sections) {
			/* Avoid the `.bss' section, it doesn't exist in the binary file. */
			if (strcmp(section_name, ".bss")) {
				replacements += replace_vendor_string(file_data + section_header.sh_offset,
						section_header.sh_size,
						(unsigned char *) section_header.sh_addr);
			}
		}
	}
	PRINT_ELF_ERRNO(); /* If there isn't elf_errno set, nothing will happend. */

	elf_end(elf_handle);

	return replacements;
}

int main(int argc, char *argv[])
{
	int option, file_descriptor;
	char *file_name;
	struct stat file_information;
	unsigned char *file_data;
	int replacements;

	PROGRAM_NAME = argv[0];
	if (argc < 2)
		PRINT_ERROR_MESSAGE("you must specify an executable to patch", true);

	options.verbose = false;
	options.analyze_elf = true;
	options.read_only = false;
	options.replace_complete_string = true;
	options.patch_all_sections = false;
	options.vendor_string = "AuthenticAMD";
	options.cpuid_bytes_distance = CPUID_BYTES_DISTANCE;

	while ((option = getopt(argc, argv, "ecd:ars:vh")) != -1) {
		switch(option) {
			case 'e':
				options.analyze_elf = false;
				break;
			case 'c':
				options.replace_complete_string = false;
				break;
			case 'd':
				options.cpuid_bytes_distance = atoi(optarg);
				break;
			case 'a':
				options.patch_all_sections = true;
				break;
			case 'r':
				options.read_only = true;
				break;
			case 's':
				if (strlen(optarg) != 12) {
					PRINT_ERROR_MESSAGE("the vendor string must be 12 characters long", true);
					break;
				}
				options.vendor_string = optarg;
				break;
			case 'v':
				options.verbose = true;
				break;
			case 'h':
				print_help();
				return 0;
			default:
				PRINT_ERROR_MESSAGE("unknown option\n", true);
				break;
		}
	}
	file_name = argv[argc - 1];

	if (options.read_only) {
		if ((file_descriptor = open(file_name, O_RDONLY)) == -1)
			PRINT_ERRNO();
	} else {
		if ((file_descriptor = open(file_name, O_RDWR)) == -1)
			PRINT_ERRNO();
	}

	if (fstat(file_descriptor, &file_information) == -1)
		PRINT_ERRNO();

	if (options.read_only) {
		if ((file_data = mmap(NULL, file_information.st_size, PROT_READ, MAP_PRIVATE,
						file_descriptor, 0)) == MAP_FAILED)
			PRINT_ERRNO();
	} else {
		if ((file_data = mmap(NULL, file_information.st_size, PROT_READ | PROT_WRITE,
						MAP_SHARED, file_descriptor, 0)) == MAP_FAILED)
			PRINT_ERRNO();
	}

	if (options.analyze_elf) {
		/* 
		 * Here we use `libelf' to look at the ELF structure to find the executable
		 * sections where the machine code is located (sections like `.text'). Then
		 * we do the substitutions only on that sections through the mmaped file.
		 * So what we need is look for the offset where those sections start and also
		 * get their lenghts.
		 */
		replacements = analyze_elf_binary(file_descriptor, file_data);
	} else {
		/*
		 * Here we just mmap the file and search in all its content in order to do
		 * the substitutions.
		 */
		replacements = replace_vendor_string(file_data, file_information.st_size, NULL);
	}

	if (options.verbose && !options.read_only && replacements)
		printf("Writing changes to the binary\n");
	munmap(file_data, file_information.st_size);
	close(file_descriptor);

	return 0;
}
