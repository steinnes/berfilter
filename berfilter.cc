/*
 * Copyright 2011 Hallgrimur H. Gunnarsson.  All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <err.h>
#include <vector>
#include "tlv.h"

char *filename;
char *prefix;
int DEBUG = 0;

struct range;

std::vector<struct range *> skip_ranges;

struct range
{
	int start;
	int end;
};

struct range *new_range(int start, int end)
{
	struct range *s = (struct range *)malloc(sizeof(struct range));
	s->start = start;
	s->end = end;
	return s;
}


TLV* tlv_by_id(TLV *tlv, int id)
{
	unsigned int i;
	if (tlv->tag.id == id)
	{
		return tlv;
	}
	for (i = 0; i < tlv->children.size(); i++)
	{
		if (tlv->children[i]->tag.id == id)
			return tlv->children[i];
	}

	return NULL;
}


bool int_in_list(int needle, int *haystack, int list_len)
{
	while (list_len > 0)
	{
		if (needle == *haystack)
			return true;
		haystack++;
		list_len--;
	}
	return false;
}

void dump_tlv_info(TLV *tlv)
{
	fprintf(stderr,"TLV:	%d\nlength: %d	nbytes: %d\nchilds: %d	depth:  %d\n",
		tlv->tag.id,
		tlv->length.length,
		tlv->nbytes,
		(int)tlv->children.size(),
		tlv->depth);
}

void error_print_value(TLV *tlv)
{
	unsigned int i;
	for (i = 0; i < tlv->length.length-1; i++)
	{
		fprintf(stderr, "%02x", tlv->value[i]);
	}
}

char *field_to_hex(TLV *tlv, int len)
{
	char hex_string[len*2];
	memset(hex_string, 0, sizeof(char)*len*2);
	char hex_seat[2];
	unsigned int i;
	unsigned short num;
	if (tlv->value != NULL)
	{
		if (tlv->length.length == 8)
		{
			for (i = 0; i < 8; i++)
			{
				// swap nibbles
				num = (unsigned short)(tlv->value[i]);
				sprintf(hex_seat, "%02x", ((num>>4)&0x0f) | ((num<<4)&0xf0));
				strncat(hex_string, hex_seat, 2);
			}
			return strdup(hex_string);
		}
	}
	return NULL;
}

int min(int a, int b)
{
	return a < b ? a : b;
}

void build_skip_ranges(TLV *tlv)
{
	unsigned int i;
	int *p;
	TLV *child;
	TLV *field_of_interest;
	char *field_value;
	int filter_records[] = 	{0,    // moCallRecord
				 1,    // mtCallRecord
				 6,    // moSMSRecord
				 7,    // mtSMSRecord
				 100}; // forwardCallRecord
	dump_tlv_info(tlv);

	for (i = 0; i < tlv->children.size(); i++)
	{
		p = (int *)filter_records;
		child = tlv->children[i];
		if (int_in_list(child->tag.id, p, 5))
		{
			printf("%s: Child %d contains the greppable field!\n", filename, child->tag.id);
			field_of_interest = tlv_by_id(child, 1); // 1 is the grep field
			if (field_of_interest != NULL)
			{
				field_value = field_to_hex(field_of_interest, 8); // our field is 8 bytes
				if (field_value == NULL)
				{
					if (DEBUG)
					{
						fprintf(stderr, "\n*******************\n");
						fprintf(stderr, "Failed to extract 8 bytes from field:");
						dump_tlv_info(field_of_interest);
						fprintf(stderr, "raw (unswapped nibble) hex data:");
						error_print_value(field_of_interest);
						fprintf(stderr, "\n*******************\n\n");
					}
					free(field_value);
					continue;
				}
				if (!strncmp(field_value, prefix, min(strlen(field_value), strlen(prefix))))
				{
					skip_ranges.push_back(
						new_range(
							child->file_offset_bytes,
							child->file_offset_bytes+child->nbytes
						));
					tlv->length.length -= child->length.length;
					tlv->nbytes -= child->nbytes;
					if (DEBUG) printf("AND A MATCH: %s! (record size: %d)\n", field_value, child->nbytes);
				}
				free(field_value);
			}
		}
		else
		{
			// drop this record!
			skip_ranges.push_back(
				new_range(
					child->file_offset_bytes,
					child->file_offset_bytes+child->nbytes
				));
			tlv->length.length -= child->length.length;
			tlv->nbytes -= child->nbytes;
		}
	}
	fprintf(stderr, "Size after: %d\n", tlv->nbytes);
	dump_tlv_info(tlv);
}

void dump(FILE *fp)
{
	struct TLV root;
	struct TLV *real_root;
	unsigned int i = 0;

	while (1)
	{
		if (feof(fp) || ferror(fp))
			break;

		if (readTLV(fp, &root, 1048576))
			break;

		printf("read TLV into root..\n");
		real_root = tlv_by_id(&root, 16);
		if (real_root == NULL)
			break;

		real_root = tlv_by_id(real_root, 1);
		if (real_root == NULL)
			break;

		build_skip_ranges(real_root);
		// now the TLV tree in real_root should be updated with correct sizes,
		// and the bytes we need to skip should be logged in skip_ranges
		int sum = 0;
		for (i = 0; i < skip_ranges.size(); i++)
		{
			struct range *it = skip_ranges[i];
			printf("Range %d = %d - %d, size=%d\n", i, it->start, it->end, (it->end - it->start));
			sum += (it->end - it->start);
		}
		printf("total bytes to skip: %d\n", sum);
	}
}

static void usage(void)
{
	fprintf(stderr, "usage: berdump -p <prefix> <file>\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -p <prefix> - prefix in hex to match the filter-field\n");
}

int main(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "p:h?d?")) != -1)
	{
		switch (c)
		{
			case 'p':
				prefix = optarg;
				break;
			case 'd':
				DEBUG = 1;
				break;
			case 'h':
			default:
				usage();
				return 0;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
	{
		if (ftell(stdin) != -1)
			dump(stdin);
		else
			usage();
		return 0;
	}

	FILE *fp = fopen(argv[0], "r");

	if (fp == NULL)
	{
		fprintf(stderr, "error opening %s: %s\n", argv[0], strerror(errno));
		return 0;
	}
	filename = argv[0];
	dump(fp);
	fclose(fp);
}

