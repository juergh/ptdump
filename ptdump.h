struct ptdump_req {
	unsigned long addr;
	int order;
};

#define PTDUMP_BASE      'P'
#define PTDUMP_DUMP      _IOWR(PTDUMP_BASE, 0, struct ptdump_req)
#define PTDUMP_WRITE     _IOWR(PTDUMP_BASE, 1, struct ptdump_req)
