
int parse_ip(int *af, const char *src, uint64_t *dst, int *bytes, int lookup, uint32_t *num_ip );

int set_nameserver(char *ns);

#define MAXHOSTS 512

#define STRICT_IP 	 0
#define ALLOW_LOOKUP 1
