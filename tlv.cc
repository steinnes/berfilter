/*
 * Copyright 2011 Hallgrimur H. Gunnarsson.  All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include "tlv.h"

static unsigned int depth = 0;

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

			length->length = (length->length << 7) | b;
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

