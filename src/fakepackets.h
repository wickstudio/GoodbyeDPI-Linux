extern int fakes_count;     /* Number of fake packet templates loaded */
extern int fakes_resend;    /* Number of times to resend each fake packet */

/* Send a fake HTTP request with optional TTL/checksum/sequence modifications */
int send_fake_http_request(const char *original_pkt,
                           const unsigned int packetLen,
                           const int is_ipv6,
                           const uint8_t set_ttl,
                           const uint8_t set_checksum,
                           const uint8_t set_seq
                          );

/* Send a fake HTTPS request with optional TTL/checksum/sequence modifications */
int send_fake_https_request(const char *original_pkt,
                            const unsigned int packetLen,
                            const int is_ipv6,
                            const uint8_t set_ttl,
                            const uint8_t set_checksum,
                            const uint8_t set_seq
                           );

/* Load a fake packet from hexadecimal string data */
int fake_load_from_hex(const char *data);

/* Create a fake TLS ClientHello packet with specified SNI (Server Name Indication) */
int fake_load_from_sni(const char *domain_name);

/* Generate random fake packets for testing or evasion */
int fake_load_random(unsigned int count, unsigned int maxsize);
