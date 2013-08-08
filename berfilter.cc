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

static int format = 0;
static unsigned int depth = 0;
static int tagpath[128];
static int record_size = 0;

char *filename;

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

struct skip_range
{
	int start;
	int end;
};

std::vector<struct skip_range> skip_ranges;

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
	printf("TLV:	%d\n \
length: %d	nbytes: %d\n \
childs: %d	depth:  %d", tlv->tag.id, tlv->length.length, tlv->nbytes, tlv->children.size(), tlv->depth);
}

void print_value(TLV *tlv)
{
	unsigned int i;
	for (i = 0; i < tlv->length.length; i++)
	{
		printf("%02x", tlv->value[i]);
	}
}

void build_skip_ranges(TLV *tlv, FILE *fp)
{
	unsigned int i;
	int *p;
	TLV *child;
	TLV *field_of_interest;
	int grep_records[] = 	{0,    // moCallRecord
				 1,    // mtCallRecord
				 6,    // moSMSRecord
				 7,    // mtSMSRecord
				 100}; // forwardCallRecord
	//dump_tlv_info(tlv);

	for (i = 0; i < tlv->children.size(); i++)
	{
		p = (int *)grep_records;
		child = tlv->children[i];
		//dump_tlv_info(child);
		if (int_in_list(child->tag.id, p, 5))
		{
			printf("%s: Child %d contains the greppable field!\n", filename, child->tag.id);
			field_of_interest = tlv_by_id(child, 1);
			if (field_of_interest != NULL)
			{
				printf("\t value=");
				print_value(field_of_interest);
				printf("\n");
			}
		}
	}
}

void dump(FILE *fp)
{
	struct TLV root;
	struct TLV *real_root;

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

		memset(tagpath, 0, sizeof(tagpath));

		switch (format)
		{
			default:
				real_root = tlv_by_id(&root, 16);
				real_root = tlv_by_id(real_root, 1);
				build_skip_ranges(real_root, fp);
				break;
		}
	}
}

static void usage(void)
{
	fprintf(stderr, "usage: berdump [options] <files>\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -f <N> : output format\n");
	fprintf(stderr, "output formats:\n");
	fprintf(stderr, "  -f0	  : Pretty tree structure\n");
	fprintf(stderr, "  -f1	  : CSV tag|value\n");
	fprintf(stderr, "  -f2	  : CSV tag|value with full tag path\n");
}

int main(int argc, char *argv[])
{
	int c, i;

	while ((c = getopt(argc, argv, "f:h?")) != -1)
	{
		switch (c)
		{
			case 'f':
				format = atoi(optarg);
				break;
			case '?':
				if (optopt == 'c')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
				return 1;
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
		dump(stdin);
		return 0;
	}

	for (i = 0; i < argc; i++)
	{
		if (strlen(argv[i]) == 1 && argv[i][0] == '-')
		{
			dump(stdin);
			continue;
		}

		FILE *fp = fopen(argv[i], "r");

		if (fp == NULL)
		{
			fprintf(stderr, "error opening %s: %s\n", argv[i], strerror(errno));
			continue;
		}
		filename = argv[i];

		dump(fp);

		fclose(fp);
	}
}

