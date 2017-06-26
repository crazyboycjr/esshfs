/* This code mostly copies from https://github.com/crossbowerbt/monocrypt */

#include "config.h"

#include <unistd.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <math.h>
#include <assert.h>

#include <openssl/aes.h>
#include <openssl/sha.h>

//#define KEY_BITS 256
#define KEY_SIZE (KEY_BITS / 8)

//#define BLOCK_BITS 128
#define BLOCK_SIZE (BLOCK_BITS / 8)

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

int encrypt_read(const char *buf, size_t size, off_t offset,
				 struct stat *stat, struct sshfs_file *sf,
				 int (*sshfs_read_func)(struct sshfs_file *, char *, size_t,  off_t))
{
	int err;
	uint64_t nonce[BLOCK_BITS / 64] = {0};
	off_t prefix_len = sizeof(nonce);
	off_t len = stat->st_size - prefix_len;

	fprintf(stderr, "encrypt_read(size=%ld, offset=%ld)\n", size, offset);
	fprintf(stderr, "len = %ld\n", len);

	if (len < 0 || offset > len) {
		return -1;
	}

	err = read_nonce(nonce, sf, sshfs_read_func);
	if (err < 0)
		return err;

	if (size > MAX_BLOCK_SEQUENCE_SIZE) {
		size = MAX_BLOCK_SEQUENCE_SIZE;
	}

	uint8_t blocks[MAX_BLOCK_SEQUENCE_SIZE + (BLOCK_SIZE)];

	uint64_t first_block_num = offset / (BLOCK_SIZE);
	size_t seq_size = size + (offset % (BLOCK_SIZE));

	if ((offset + size) % (BLOCK_SIZE) != 0)
		seq_size += (BLOCK_SIZE) - ((offset + size) % (BLOCK_SIZE));

	/* read sequence of blocks */

	size_t read_size = seq_size;
	if (seq_size + first_block_num * BLOCK_SIZE >= (size_t)len)
		read_size = len - first_block_num * BLOCK_SIZE;

	int ret = sshfs_read_func(sf, (void *)blocks, read_size,
							  first_block_num * BLOCK_SIZE + prefix_len);
	
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

	memset((void *)buf, 0, size);
	memcpy((void *)buf, blocks + (offset % BLOCK_SIZE), size);

    return size;
}

int encrypt_write(const char *buf, size_t size, off_t offset,
				  struct stat *stat, struct sshfs_file *sf,
				  int (*sshfs_write_func)(struct sshfs_file *, const char *, size_t,  off_t),
				  int (*sshfs_read_func)(struct sshfs_file *, char *, size_t,  off_t))
{
	int err;
	uint64_t nonce[BLOCK_BITS / 64] = {0};
	off_t prefix_len = sizeof(nonce);
	off_t len = stat->st_size - prefix_len;

	fprintf(stderr, "hello\n");
	fprintf(stderr, "encrypt_write(size=%ld, offset=%ld)\n", size, offset);
	fprintf(stderr, "len = %ld\n", len);

	if (len < 0 || offset > len) {
		return -1;
	}

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
	fprintf(stderr, "hello\n");
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

	/* write it back in encrypted file */

	err = sshfs_write_func(sf, (void *)blocks, seq_size,
						   first_block_num * BLOCK_SIZE + prefix_len);

	if (err) {
		fprintf(stderr, "sshfs_write_func error\n");
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
