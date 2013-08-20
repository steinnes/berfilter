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
	int isExtended;
};

struct TLV
{
        struct tag tag;
        struct length length;
        unsigned int nbytes;
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
		length->isExtended = 1;
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

	memset(tlv, 0, sizeof(struct TLV));

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
			child->parent = tlv;

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

		child->parent = tlv;
		tlv->children.push_back(child);
	}

	return 0;
}

int writeTag(struct tag tag, FILE *fp)
{
        int r = fwrite((char *)&(tag.tag), sizeof(char), tag.nbytes, fp);

        if (r != tag.nbytes)
                return 1;
        return 0;
}

int writeLen(struct length len, FILE *fp)
{
        unsigned int i;
        char initial_octet;
	char octet;

        if (len.isExtended)
        {
                initial_octet = 0;
                initial_octet = (LEN_MASK | len.nbytes);
                fwrite(&initial_octet, 1, 1, fp);
        }
        int relevant_mask = 0;
        for (i = 0; i < len.nbytes; i++)
        {
                relevant_mask |= 0xFF;
                relevant_mask <<= 8;
        }
	octet = len.length & relevant_mask;
        unsigned int r = fwrite(&octet, 1, len.nbytes, fp);
        if (r != len.nbytes)
                return 1;
        return 0;
}

int writeTLV(TLV *tlv, FILE *fp)
{
	unsigned int i;
	if (writeTag(tlv->tag, fp))
	{
		printf("Couldn't write tag!\n");
		return 1;
	}
	if (writeLen(tlv->length, fp))
	{
		printf("Couldn't write length!\n");
		return 1;
	}
	if (tlv->tag.isPrimitive)
	{
		int written = fwrite(tlv->value, sizeof(char), tlv->nbytes, fp);
	}
	else
	{
		for (i = 0; i < tlv->children.size(); i++)
			writeTLV(tlv->children[i], fp);
	}
	return 0;
}

TLV *tlv_child_by_id(TLV *tlv, int id)
{
	unsigned int i;
	for (i = 0; i < tlv->children.size(); i++)
	{
		if (tlv->children[i]->tag.id == id)
			return tlv->children[i];
	}
	return NULL;
}


TLV* tlv_by_id(TLV *tlv, int id)
{
	if (tlv->tag.id == id)
	{
		return tlv;
	}
	return tlv_child_by_id(tlv, id);
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

void tlv_update_size(TLV *tlv, int delta)
{
	tlv->nbytes += delta;
	if (tlv->parent != NULL)
		tlv_update_size(tlv->parent, delta);
}

void tlv_delete(TLV *tlv)
{
	unsigned int my_size = tlv->nbytes;
	tlv_update_size(tlv->parent, -my_size);
	//tlv->parent->length.length -= 1; // XXX: KANNSKI EKKI NAUÐSYNLEGT
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
	fprintf(stderr, "printing %d bytes:\n", tlv->length.length);
	for (i = 0; i < tlv->length.length-1; i++)
	{
		fprintf(stderr, "%02x", tlv->value[i]);
	}
}

char *field_to_hex(TLV *tlv, unsigned int len)
{
	char hex_string[len*2];
	memset(hex_string, 0, sizeof(char)*len*2);
	char hex_seat[2];
	unsigned int i;
	unsigned short num;
	if (tlv->value != NULL)
	{
		for (i = 0; i < len; i++)
		{
			// swap nibbles
			num = (unsigned short)(tlv->value[i]);
			sprintf(hex_seat, "%02x", ((num>>4)&0x0f) | ((num<<4)&0xf0));
			strncat(hex_string, hex_seat, 2);
		}
		return strdup(hex_string);
	}
	return NULL;
}

int min(int a, int b)
{
	return a < b ? a : b;
}

// filters out TLVs from the 2nd level, based on whether the record is one of
// "filter_records" and the "field of interest" (1, or ServedIMSI) matches a
// given pattern
// returns number of records deleted
unsigned int filter_tree(TLV *tlv)
{
	unsigned int i = 0;
	unsigned int n_deleted = 0;
	TLV *child;
	TLV *field_of_interest;
	char *field_value;
	int filter_records[] = 	{0,    // moCallRecord
				 1,    // mtCallRecord
				 6,    // moSMSRecord
				 7,    // mtSMSRecord
				 100}; // forwardCallRecord

	int total_records = 0;
	int field_to_look_for = 1;

	for (std::vector<struct TLV *>::iterator it(tlv->children.begin()); it != tlv->children.end(); it++)
	{
		total_records++;
		child = *it;
		if (int_in_list(child->tag.id, (int *)filter_records, 5))
		{
			printf("%s: Child %d (%d) contains the filter field!\n", filename, i, child->tag.id);
			if (child->tag.id == 7)
				field_to_look_for = 2;
			else
				field_to_look_for = 1;

			field_of_interest = tlv_child_by_id(child, field_to_look_for);
			if (field_of_interest == NULL)
				continue;

			field_value = field_to_hex(field_of_interest, field_of_interest->length.length);
			if (field_value == NULL)
			{
				if (DEBUG)
				{
					fprintf(stderr, "\n*******************\n");
					fprintf(stderr, "Failed to extract 8 bytes from field:\n");
					dump_tlv_info(field_of_interest);
					fprintf(stderr, "raw (unswapped nibble) hex data:\n");
					error_print_value(field_of_interest);
					fprintf(stderr, "\n*******************\n\n");
				}
				continue;
			}
			// actual comparison
			if (!strncmp(field_value, prefix, min(strlen(field_value), strlen(prefix))))
			{
				// We have a match, skip this record
				tlv_delete(child);
				tlv->children.erase(it);
				n_deleted++;
			}
			else
				printf("Keeping record %d (%d), size:%d\n", i, child->tag.id, child->nbytes);
			free(field_value);
		}
		else // Not one of our "filter" records, we skip it!
		{
			tlv_delete(child);
			tlv->children.erase(it);
			n_deleted++;
		}
	}
	printf("total records: %d\n", total_records);
	return n_deleted;
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
	char out_file[256];
	memset(&out_file, 0, 256);
	snprintf(out_file, 255, "%s.filtered", filename);
	FILE *out = fopen(out_file, "w+");
	int n_deleted = 0;

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

		n_deleted = filter_tree(real_root);
		printf("I deleted %d records from %s\n", n_deleted, filename);
		printf("Writing file: %s.filtered\n", filename);
		writeTLV(real_root, out);
	}
}

static void usage(void)
{
	fprintf(stderr, "usage: berfilter -p <prefix> <file>\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -p <prefix> - prefix in hex to match the filter-field\n");
}

int main(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "p:h?:d?")) != -1)
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
	if (prefix == NULL)
	{
		usage();
		return 0;
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

