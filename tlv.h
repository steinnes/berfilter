#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <err.h>
#include <vector>

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

int readTag(FILE *fp, struct tag *tag);

int readLen(FILE *fp, struct length *length);

int readTLV(FILE *fp, struct TLV *tlv, unsigned int limit);

