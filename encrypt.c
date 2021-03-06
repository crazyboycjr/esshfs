/* Some of the code copies from https://github.com/crossbowerbt/monocrypt */

#include "config.h"

#include <unistd.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <execinfo.h>

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <math.h>
#include <assert.h>

#include <openssl/aes.h>
#include <openssl/sha.h>

#ifdef MACRO_DEBUG
#define debug(...)						\
	do { ; fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define debug(...)
#endif

//#define KEY_BITS 256
#define KEY_SIZE (KEY_BITS / 8)

//#define BLOCK_BITS 128
#define BLOCK_SIZE (BLOCK_BITS / 8)

#define PADDING_OFF (BLOCK_SIZE)

#define passphrase_hash prim_passphrase_sha256

#define enc_block prim_enc_block_aes256
#define dec_block prim_dec_block_aes256

static uint64_t main_key[KEY_BITS / 64] = {0};

static void
prim_passphrase_sha256(uint8_t digest[SHA256_DIGEST_LENGTH],
                       const uint8_t *passwd, size_t passwdsz,
                       const uint8_t *salt, size_t saltsz)
{
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, passwd, passwdsz);
    SHA256_Update(&ctx, salt, saltsz);
    SHA256_Final(digest, &ctx);
}

void collect_passphrase()
{
	char *passphrase = getpass("Input AES passphrase: ");
	uint8_t nonce[BLOCK_SIZE] = {0};
	passphrase_hash((uint8_t *)main_key, (uint8_t *) passphrase,
					strlen(passphrase), (uint8_t *)nonce, sizeof(nonce));
}

static void
prim_enc_block_aes256(uint8_t cipher[BLOCK_SIZE],
                      const uint8_t plain[BLOCK_SIZE],
                      const uint8_t key[KEY_SIZE])
{
    AES_KEY aes_key;

    AES_set_encrypt_key(key, KEY_BITS, &aes_key);
    AES_encrypt(plain, cipher, &aes_key);
}

static void
prim_dec_block_aes256(const uint8_t cipher[BLOCK_SIZE],
                      uint8_t plain[BLOCK_SIZE],
                      const uint8_t key[KEY_SIZE])
{
    AES_KEY aes_key;

    AES_set_decrypt_key(key, KEY_BITS, &aes_key);
    AES_decrypt(cipher, plain, &aes_key);
}

static void
ctr_key_for_block(uint8_t block_key[BLOCK_SIZE],
                  const uint64_t main_key[KEY_BITS/64],
                  const uint64_t nonce[BLOCK_BITS/64],
                  uint64_t block_num)
{
    uint64_t nonce_indexed[BLOCK_BITS/64] = {
        nonce[0], nonce[1] ^ htobe64(block_num)
    };

    enc_block(block_key, (const uint8_t *)nonce_indexed, (const uint8_t *)main_key);
}

static void
ctr_xor_block(uint64_t block[BLOCK_BITS/64], const uint64_t block_key[BLOCK_BITS/64])
{
    register int i;

    for(i = 0; i < BLOCK_BITS/64; i++) {
        block[i] ^= block_key[i];
    }
}

static void
enc_dec_block_sequence(uint8_t *blocks, size_t size,
                       const uint64_t main_key[KEY_BITS/64],
                       const uint64_t nonce[BLOCK_BITS/64],
                       uint64_t first_block_num)
{
    uint8_t block_key[BLOCK_SIZE];
    register size_t i;

    assert(size % (BLOCK_SIZE) == 0);

    for(i = 0; i < size; i += (BLOCK_SIZE)) {
        ctr_key_for_block(block_key, main_key, nonce, first_block_num + (i/(BLOCK_SIZE)));
        ctr_xor_block((uint64_t *)&blocks[i], (uint64_t *)block_key);
    }
}

#define MAX_BLOCK_SEQUENCE_SIZE ((BLOCK_SIZE) * 256)

struct sshfs_file;

int read_nonce(uint64_t *nonce, struct sshfs_file *sf,
			   int (*sshfs_read_func)(struct sshfs_file *, char *, size_t,  off_t))
{
	char nonce_buf[BLOCK_SIZE];
	int ret = sshfs_read_func(sf, nonce_buf, BLOCK_SIZE, 0);
	fprintf(stderr, "ret = %d\n", ret);
	for (int i = 0; i < BLOCK_SIZE; i++) {
		fprintf(stderr, "%#.2x", nonce_buf[i]);
	}
	if (ret < 0) {
		return ret;
	}
	if (ret < BLOCK_SIZE) {
		fprintf(stderr, "read nonce error\n");
		return -1;
	}
	memcpy((void *)nonce, nonce_buf, BLOCK_SIZE);
	return 0;
}

int read_padding(int *padding, struct sshfs_file *sf,
			   int (*sshfs_read_func)(struct sshfs_file *, char *, size_t,  off_t))
{
	char buf[BLOCK_SIZE];
	int ret = sshfs_read_func(sf, buf, BLOCK_SIZE, PADDING_OFF);
	debug("read_padding: ret = %d\n", ret);
	for (int i = 0; i < BLOCK_SIZE; i++) {
		debug("%#.2x", buf[i]);
	}
	debug("\n");
	if (ret < 0) {
		return ret;
	}
	if (ret < BLOCK_SIZE) {
		fprintf(stderr, "read nonce error\n");
		return -1;
	}
	*padding = (int)buf[0];
	return 0;
}

int write_padding(int padding, struct sshfs_file *sf,
			   int (*sshfs_write_func)(struct sshfs_file *, const char *, size_t,  off_t))
{
	char buf[BLOCK_SIZE];
	memset(buf, 0, sizeof buf);
	assert(0 <= padding && padding <= BLOCK_SIZE);
	buf[0] = padding;
	debug("padding = %d\n", padding);
	return sshfs_write_func(sf, buf, BLOCK_SIZE, PADDING_OFF);
}

uint8_t* dec_str(const char *buf, size_t len, int *dec_len)
{
	// hard coded nonce
	uint64_t nonce[BLOCK_BITS / 64] = {0};
	//size_t len = strlen(buf);

	debug("enc_dec_str: len = %ld\n", len);

	assert(len <= MAX_BLOCK_SEQUENCE_SIZE);

	uint8_t *blocks = (uint8_t *)malloc(MAX_BLOCK_SEQUENCE_SIZE + BLOCK_SIZE);

	int padding_length = buf[0];
	memcpy(blocks, buf + BLOCK_SIZE, len);

	if (len % (BLOCK_SIZE) != 0)
		len += (BLOCK_SIZE) - (len % (BLOCK_SIZE));

	enc_dec_block_sequence(blocks, len,
						   main_key, nonce, 0);

	for (int i = 0; i < (int)len; i++)
		debug("%.2x ", blocks[i]);
	debug("\n");
	blocks[len - padding_length] = '\0';
	*dec_len = len - padding_length;
    return blocks;
}
uint8_t* enc_str(const char *buf, size_t len, int *enc_len)
{
	// hard coded nonce
	uint64_t nonce[BLOCK_BITS / 64] = {0};
	//size_t len = strlen(buf);

	debug("enc_dec_str: len = %ld\n", len);

	assert(len <= MAX_BLOCK_SEQUENCE_SIZE);

	uint8_t *blocks = (uint8_t *)malloc(MAX_BLOCK_SEQUENCE_SIZE + BLOCK_SIZE);

	blocks[0] = BLOCK_SIZE - len % BLOCK_SIZE;
	if (blocks[0] == BLOCK_SIZE)
		blocks[0] = 0;
	memcpy(blocks + BLOCK_SIZE, buf, len);

	if (len % (BLOCK_SIZE) != 0)
		len += (BLOCK_SIZE) - (len % (BLOCK_SIZE));

	enc_dec_block_sequence(blocks + BLOCK_SIZE, len,
						   main_key, nonce, 0);

	for (int i = 0; i < (int)len; i++)
		debug("%.2x ", blocks[i + BLOCK_SIZE]);
	debug("\n");
	*enc_len = len + BLOCK_SIZE;
    return blocks;
}

char *base64_encode(const unsigned char *data, size_t, size_t *);
unsigned char *base64_decode(const char *data, size_t, size_t *);

char* decrypt_path(const char *path)
{
	debug("decrypt_path(path = %s)\n", path);

	char *tpath = strndup(path, strlen(path));
	size_t length = strlen(path);
	char *dpath = (char *)malloc(length);
	memset(dpath, 0, length);
	int curlen = 0;
	int first_time = 1;
	for (char *ptr = strtok(tpath, "/"); ptr;
		 ptr = strtok(NULL, "/"), first_time = 0) {
		int len = strlen(ptr);
		if (len == 0) continue;
		if (!first_time || path[0] == '/') {
			strcat(dpath, "/");
			curlen++;
		}
		if (strcmp(ptr, "..") == 0) {
			strcat(dpath, "..");
			curlen += 2;
			continue;
		}
		if (strcmp(ptr, ".") == 0) {
			strcat(dpath, ".");
			curlen += 1;
			continue;
		}
		int dec_len = 0, b64_len = 0;
		char *tempstr = base64_decode(ptr, len, &b64_len);
		int temp_len = b64_len;
		debug("temp_len = %d\n", temp_len);
		for (int i = 0; i < temp_len; i++)
			debug("%.2x ", tempstr[i]);
		debug("\n");
		char *bptr = dec_str(tempstr, b64_len, &dec_len);
		//char *bptr = (char *)base64_decode((char *)enc_dec_str(ptr));
		//char *bptr = dec_str((char *)base64_decode((char *)ptr));
		//char *bptr = base64_decode((char *)ptr);
		strcat(dpath, bptr);
		curlen += strlen(bptr);
	}
	if (curlen == 0) {
		dpath[curlen++] = '/';
	}
	debug("decrypt_path: curlen = %d\n", curlen);
	dpath[curlen] = '\0';
	debug("dncrypt_path: dpath = %s\n", dpath);
	return dpath;
}

void print_backtrace(void)
{
	int j, nptrs;
#define BT_BUF_SIZE 2048
	void *buffer[BT_BUF_SIZE];
	char **strings;

	nptrs = backtrace(buffer, BT_BUF_SIZE);
	printf("backtrace() returned %d addresses\n", nptrs);

	/* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
 	 would produce similar output to the following: */

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		exit(EXIT_FAILURE);
	}

	for (j = 0; j < nptrs; j++)
		printf("%s\n", strings[j]);

	free(strings);
}


char* encrypt_path(const char *path)
{
	debug("encrypt_path(path = %s)\n", path);

	char *tpath = strndup(path, strlen(path));

	size_t length = strlen(path);
	int max_interval = 0, last_slash = 0, num_slash = 0;
	for (int i = 0; i < (int)length; i++) {
		if (path[i] == '/') {
			if (max_interval < i - last_slash)
				max_interval = i - last_slash;
			last_slash = i;
			num_slash++;
		}
	}
	if (max_interval < (int)length - last_slash)
		max_interval = (int)length - last_slash;
	num_slash++;

	/* I change below + 100 and all seem to be fine........ no more xuanxue error...... */
	length = (max_interval / BLOCK_SIZE + 100) * BLOCK_SIZE * num_slash * 4 / 3 + length;
	char *epath = (char *)malloc(length);
	memset(epath, 0, length);

	int curlen = 0;
	int first_time = 1;
	for (char *ptr = strtok(tpath, "/"); ptr;
		 ptr = strtok(NULL, "/"), first_time = 0) {
		int len = strlen(ptr);
		debug("f**k: %s %d\n", ptr, first_time);
		if (len == 0) continue;
		if (!first_time || path[0] == '/') {
			strcat(epath, "/");
			curlen++;
		}
		if (strcmp(ptr, "..") == 0) {
			strcat(epath, "..");
			curlen += 2;
			continue;
		}
		if (strcmp(ptr, ".") == 0) {
			strcat(epath, ".");
			curlen += 1;
			continue;
		}
		int enc_len = 0, b64_len = 0;
		uint8_t *tempstr = enc_str(ptr, len, &enc_len);
		int temp_len = enc_len;
		debug("temp_len = %d\n", temp_len);
		for (int i = 0; i < temp_len; i++)
			debug("%.2x ", tempstr[i]);
		debug("\n");
		char *bptr = base64_encode(tempstr, enc_len, &b64_len);
		//char *bptr = base64_encode(enc_str(ptr));
		//char *bptr = base64_encode(ptr);
		strcat(epath, bptr);
		curlen += strlen(bptr);
	}
	if (curlen == 0) {
		epath[curlen++] = '/';
	}
	debug("encrypt_path: curlen = %d\n", curlen);
	epath[curlen] = '\0';
	debug("encrypt_path: epath = %s\n", epath);
	return epath;
}

int encrypt_read(char *buf, size_t size, off_t offset,
				 struct stat *stat, struct sshfs_file *sf,
				 int (*sshfs_read_func)(struct sshfs_file *, char *, size_t,  off_t))
{
	int err;
	uint64_t nonce[BLOCK_BITS / 64] = {0};
	off_t prefix_len = sizeof(nonce) + BLOCK_SIZE;
	off_t len = stat->st_size - prefix_len;
	//off_t len = stat->st_size;

	fprintf(stderr, "encrypt_read(size=%ld, offset=%ld)\n", size, offset);
	fprintf(stderr, "len = %ld\n", len);

	if (len < 0 || offset > len) {
		return -1;
	}
	/*
	if (offset + size > len) {
		size = len - offset;
	}
	*/

	int padding_length = 0;
	err = read_padding(&padding_length, sf, sshfs_read_func);
	if (err < 0)
		return err;
	debug("padding_length = %d\n", padding_length);

	err = read_nonce(nonce, sf, sshfs_read_func);
	if (err < 0)
		return err;

	int tsize = size;
	if (tsize > MAX_BLOCK_SEQUENCE_SIZE) {
		tsize = MAX_BLOCK_SEQUENCE_SIZE;
	}
	memset(buf, 0, size);
	for (off_t off = offset; off < len - padding_length && off < offset + size; off += tsize) {

		uint8_t blocks[MAX_BLOCK_SEQUENCE_SIZE + (BLOCK_SIZE)];

		uint64_t first_block_num = off / (BLOCK_SIZE);
		size_t seq_size = tsize + (off % (BLOCK_SIZE));

		if ((off + tsize) % (BLOCK_SIZE) != 0)
			seq_size += (BLOCK_SIZE) - ((off + tsize) % (BLOCK_SIZE));

		size_t read_size = seq_size;
		if (seq_size + first_block_num * BLOCK_SIZE >= (size_t)len)
			read_size = len - first_block_num * BLOCK_SIZE;

		debug("read_size = %d", read_size);
		int ret = sshfs_read_func(sf, (void *)blocks, read_size,
								  first_block_num * BLOCK_SIZE + prefix_len);
		
		if (ret != (int)read_size) {
			fprintf(stderr,
					"sshfs_read_func(): read only %d out of %ld bytes",
					ret, read_size);
			return -1;
		}

		enc_dec_block_sequence(blocks, read_size,
							   main_key, nonce, first_block_num);

		debug("**********************%d %d %d %d %d %d\n", offset, size, off, tsize, len, padding_length);
		if (off + tsize >= len - padding_length) {
			tsize -= off + tsize - (len - padding_length);
			size = off + tsize - offset;
		}
		debug("size = %ld\n", size);
		//memset(buf, 0, size);
		memcpy(buf + off - offset, blocks + (off % BLOCK_SIZE), tsize);
		for (int i = 0; i < tsize; i++)
			debug("%.2x ", blocks[off % BLOCK_SIZE + i]);
		debug("\n");
	}

	debug("return size = %d\n", size);
    return size;
}

int encrypt_write(const char *buf, size_t size, off_t offset,
				  struct stat *stat, struct sshfs_file *sf,
				  int (*sshfs_write_func)(struct sshfs_file *, const char *, size_t,  off_t),
				  int (*sshfs_read_func)(struct sshfs_file *, char *, size_t,  off_t))
{
	int err;
	uint64_t nonce[BLOCK_BITS / 64] = {0};
	off_t prefix_len = sizeof(nonce) + BLOCK_SIZE;
	off_t len = stat->st_size - prefix_len;
	//off_t len = stat->st_size;

	fprintf(stderr, "hello\n");
	fprintf(stderr, "encrypt_write(size=%ld, offset=%ld)\n", size, offset);
	fprintf(stderr, "len = %ld\n", len);

	if (len < 0 || offset > len) {
		return -1;
	}
	int padding_length;
	err = read_padding(&padding_length, sf, sshfs_read_func);
	if (err < 0)
		return err;
	debug("padding_length = %d\n", padding_length);

	err = read_nonce(nonce, sf, sshfs_read_func);
	if (err < 0)
		return err;

	if (size > MAX_BLOCK_SEQUENCE_SIZE) {
		size = MAX_BLOCK_SEQUENCE_SIZE;
	}

	/* allocate space for sequence */

	// we add an extra block to handle unaligned reads:
	uint8_t blocks[MAX_BLOCK_SEQUENCE_SIZE + (BLOCK_SIZE)];
	memset(blocks, 0, sizeof blocks);

	uint64_t first_block_num = offset / (BLOCK_SIZE);
	size_t seq_size = size + (offset % (BLOCK_SIZE));

	/* fill extra bytes to obtain a sequence length
	   which is a multiple of the block size */

	if ((offset + size) % (BLOCK_SIZE) != 0)
		seq_size += (BLOCK_SIZE) - ((offset + size) % (BLOCK_SIZE));

	/* read sequence of blocks */

	size_t read_size = seq_size;
	if (seq_size + first_block_num * BLOCK_SIZE >= (size_t)len)
		read_size = len - first_block_num * BLOCK_SIZE;

	debug("read_size = %d seq_size = %d\n", read_size, seq_size);
	int ret = sshfs_read_func(sf, (void *)blocks, read_size,
						  first_block_num * BLOCK_SIZE + prefix_len);

	fprintf(stderr, "hello\n");
	if (ret != (int)read_size) {
	fprintf(stderr, "hello2\n");
		fprintf(stderr,
				"sshfs_read_func(): read only %d out of %ld bytes",
				ret, read_size);
		return -1;
	}

	/* decrypt sequence of blocks */

	enc_dec_block_sequence(blocks, read_size,
						   main_key, nonce, first_block_num);

	memcpy(blocks + (offset % (BLOCK_SIZE)), buf, size);

	/* re-encrypt sequence */

	enc_dec_block_sequence(blocks, seq_size,
						   main_key, nonce, first_block_num);
	for (int i = 0; i < seq_size; i++) {
		debug("%.2x ", blocks[i]);
	}
	debug("\n");

	/* write it back in encrypted file */

	err = sshfs_write_func(sf, (void *)blocks, seq_size,
						   first_block_num * BLOCK_SIZE + prefix_len);

	if (err) {
		fprintf(stderr, "sshfs_write_func error\n");
		return err;
	}
	off_t end = size + first_block_num * BLOCK_SIZE;
	debug("--------------------------%ld %d %d\n", end, len, BLOCK_SIZE);
	if (end >= len - BLOCK_SIZE) {
		/* Append an extra block indicates the bytes of padding */
		padding_length = BLOCK_SIZE - end % BLOCK_SIZE;
		if (padding_length == BLOCK_SIZE)
			padding_length = 0;
		err = write_padding(padding_length, sf, sshfs_write_func);
		if (err < 0)
			return err;
	}

    return size;
}

void generate_nonce(char *buf)
{
	for (int i = 0; i < (BLOCK_BITS / 8); i++)
		buf[i] = rand() & 0xff;
}

void encrypt_init()
{
	srand((unsigned)time(0));
}

/* this code below extracts from stackoverflow, I do some modification */

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '-', '_'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {

	//size_t input_length = strlen((char *)data);
    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;
	encoded_data[*output_length] = '\0';

    for (int i = 0, j = 0; i < (int)input_length;) {

        uint32_t octet_a = i < (int)input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < (int)input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < (int)input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

	//size_t input_length = strlen(data);
    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length + 1);
    if (decoded_data == NULL) return NULL;
	decoded_data[*output_length] = '\0';

    for (int i = 0, j = 0; i < (int)input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < (int)(*output_length)) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < (int)(*output_length)) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < (int)(*output_length)) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

