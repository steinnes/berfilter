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

char *filename;
char *prefix;
int DEBUG = 0;
static unsigned int depth = 0;

struct range;

enum
{
	CLASS_MASK	= 0xC0,
	TYPE_MASK	= 0x20,
	TAG_MASK	= 0x1F,
	LEN_XTND	= 0x80,
	LEN_MASK	= 0x7F
};

struct tag
{
	int cls;
	int isPrimitive;
	int id;
	int tag;
	int nbytes;
};

struct length
{
        unsigned int length;
        unsigned int nbytes;
};

struct TLV
{
        struct tag tag;
        struct length length;
        unsigned int nbytes;
        long file_offset_bytes;
        unsigned int depth;
        unsigned char *value;
        TLV *parent;
        std::vector<struct TLV *> children;
};


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

int readTag(FILE *fp, struct tag *tag)
{
	memset(tag, 0, sizeof(struct tag));

	int b = fgetc(fp);

	if (b == EOF)
		return 1;

	tag->nbytes = 1;

	tag->tag = b;
	tag->cls = b & CLASS_MASK;
	tag->isPrimitive = (b & TYPE_MASK) == 0;

	tag->id = b & TAG_MASK;

	if (tag->id == TAG_MASK)
	{
		// Long tag, encoded as a sequence of 7-bit values

		tag->id = 0;

		do
		{
			b = fgetc(fp);

			if (b == EOF)
				return 1;

			tag->nbytes++;
			tag->id = (tag->id << 7) | (b & LEN_MASK);

		} while ((b & LEN_XTND) == LEN_XTND);
	}

	return 0;
}

int readLen(FILE *fp, struct length *length)
{
	int b, i;

	memset(length, 0, sizeof(struct length));

	b = fgetc(fp);

	if (b == EOF)
		return 1;

	length->nbytes = 1;
	length->length = b;

	if ((length->length & LEN_XTND) == LEN_XTND)
	{
		int numoct = length->length & LEN_MASK;

		length->length = 0;

		if (numoct == 0)
			return 0;

		for (i = 0; i < numoct; i++)
		{
			b = fgetc(fp);

			if (b == EOF)
				return 1;

			length->length = (length->length << 8) | b;
			length->nbytes++;
		}
	}

	return 0;
}

int readTLV(FILE *fp, struct TLV *tlv, unsigned int limit)
{
	int n = 0;
	int i;
	long file_offset;

	memset(tlv, 0, sizeof(struct TLV));
	file_offset = ftell(fp);
	if (file_offset == -1)
		printf("ftell encountered error: %s\n", strerror(errno));
	tlv->file_offset_bytes = file_offset;

	if (readTag(fp, &tlv->tag))
		return 1;

	tlv->nbytes += tlv->tag.nbytes;

	if (tlv->nbytes >= limit)
		return 1;

	if (readLen(fp, &tlv->length))
		return 1;

	tlv->nbytes += tlv->length.nbytes;
	tlv->depth = depth;

	int length = tlv->length.length;

	if (tlv->nbytes >= limit)
	{
		if (length == 0)
			return 0;

		return 1;
	}

	if (tlv->tag.isPrimitive)
	{
		// Primitive definite-length method

		if (length == 0)
			return 0;

		tlv->value = (unsigned char *)malloc(length);

		if (tlv->value == NULL)
			err(1, "malloc");

		if (!fread(tlv->value, length, 1, fp))
			return 1;

		tlv->nbytes += length;

		return 0;
	}

	if (length > 0)
	{
		// Constructed definite-length method

		struct TLV *child;
		i = 0;

		while (i < length)
		{
			depth++;

			child = (struct TLV *)malloc(sizeof(struct TLV));

			if (child == NULL)
				err(1, "malloc");

			if (readTLV(fp, child, length-i))
			{
				depth--;
				return 1;
			}

			depth--;

			i += child->nbytes;
			tlv->nbytes += child->nbytes;
			tlv->children.push_back(child);
		}

		return 0;
	}

	// Constructed indefinite-length method

	struct TLV *child;

	while (1)
	{
		depth++;

		child = (struct TLV *)malloc(sizeof(struct TLV));

		if (child == NULL)
			err(1, "malloc");

		n = readTLV(fp, child, limit-tlv->nbytes);

		depth--;

		tlv->nbytes += child->nbytes;

		if (n == 1)
			return 1;

		if (child->tag.tag == 0 && child->length.length == 0)
			break;

		tlv->children.push_back(child);
	}

	return 0;
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
			field_of_interest = tlv_by_id(child, 1);
			if (field_of_interest != NULL)
			{
				field_value = field_to_hex(field_of_interest, 8); // our field is 8 bytes
				if (field_value == NULL)
				{
					fprintf(stderr, "\n*******************\n");
					fprintf(stderr, "Failed to extract 8 bytes from field:");
					dump_tlv_info(field_of_interest);
					fprintf(stderr, "raw (unswapped nibble) hex data:");
					error_print_value(field_of_interest);
					fprintf(stderr, "\n*******************\n\n");
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
					printf("AND A MATCH: %s! (record size: %d)\n", field_value, child->nbytes);
				}
				free(field_value);
			}
		}
		else
		{
			// drop this record!
			
		}
	}
	printf("Done...\n");
	dump_tlv_info(tlv);
}

void dump(FILE *fp)
{
	struct TLV root;
	struct TLV *real_root;
	unsigned int i = 0;

	/*
		moCallRecord (MOCallRecord): 16 / 1 / 0 / 1
		mtCallRecord (MTCallRecord): 16 / 1 / 1 / 1

		moSMSRecord (MOSMSRecord):   16 / 1 / 6 / 1
		mtSMSRecord (MTSMSRecord):   16 / 1 / 7 / 1
	*/

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

	while ((c = getopt(argc, argv, "p:h?")) != -1)
	{
		switch (c)
		{
			case 'p':
				prefix = optarg;
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

