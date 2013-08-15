#include "mysql_password/my_global.h"
#include "mysql_password/mysql_com.h"
#include "mysql_password/sha1.h"
#include <stdio.h>
#include <string.h>
#include <math.h>


static inline uint8 char_val(uint8 X)
{
  return (uint) (X >= '0' && X <= '9' ? X-'0' :
      X >= 'A' && X <= 'Z' ? X-'A'+10 : X-'a'+10);
}

/*
    Convert given asciiz string of hex (0..9 a..f) characters to octet
    sequence.
  SYNOPSIS
    hex2octet()
    to        OUT buffer to place result; must be at least len/2 bytes
    str, len  IN  begin, length for character string; str and to may not
                  overlap; len % 2 == 0
*/ 

static void
hex2octet(uint8 *to, const char *str, uint len)
{
  const char *str_end= str + len;
  while (str < str_end)
  {
    register char tmp= char_val(*str++);
    *to++= (tmp << 4) | char_val(*str++);
  }
}

/*
  New (MySQL 3.21+) random generation structure initialization
  SYNOPSIS
    randominit()
    rand_st    OUT  Structure to initialize
    seed1      IN   First initialization parameter
    seed2      IN   Second initialization parameter
*/

void randominit(struct rand_struct *rand_st, ulong seed1, ulong seed2)
{                                               /* For mysql 3.21.# */
#ifdef HAVE_purify
  bzero((char*) rand_st,sizeof(*rand_st));      /* Avoid UMC varnings */
#endif
  rand_st->max_value= 0x3FFFFFFFL;
  rand_st->max_value_dbl=(double) rand_st->max_value;
  rand_st->seed1=seed1%rand_st->max_value ;
  rand_st->seed2=seed2%rand_st->max_value;
}


/*
    Generate random number.
  SYNOPSIS
    my_rnd()
    rand_st    INOUT  Structure used for number generation
  RETURN VALUE
    generated pseudo random number
*/

double my_rnd(struct rand_struct *rand_st)
{
  rand_st->seed1=(rand_st->seed1*3+rand_st->seed2) % rand_st->max_value;
  rand_st->seed2=(rand_st->seed1+rand_st->seed2+33) % rand_st->max_value;
  return (((double) rand_st->seed1)/rand_st->max_value_dbl);
}

/*
    Encrypt/Decrypt function used for password encryption in authentication.
    Simple XOR is used here but it is OK as we crypt random strings. Note,
    that XOR(s1, XOR(s1, s2)) == s2, XOR(s1, s2) == XOR(s2, s1)
  SYNOPSIS
    my_crypt()
    to      OUT buffer to hold crypted string; must be at least len bytes
                long; to and s1 (or s2) may be the same.
    s1, s2  IN  input strings (of equal length)
    len     IN  length of s1 and s2
*/



static void
my_crypt(char *to, const uchar *s1, const uchar *s2, uint len)
{
  const uint8 *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
}

void
scramble_with_hash_stage1(char *to, const char *message, const unsigned char *hash_stage1)
{
  SHA1_CONTEXT sha1_context;
  uint8 hash_stage2[SHA1_HASH_SIZE];

  /* stage 2: hash stage 1; note that hash_stage2 is stored in the database */
  mysql_sha1_reset(&sha1_context);
  mysql_sha1_input(&sha1_context, hash_stage1, SHA1_HASH_SIZE);
  mysql_sha1_result(&sha1_context, hash_stage2);
  /* create crypt string as sha1(message, hash_stage2) */;
  mysql_sha1_reset(&sha1_context);
  mysql_sha1_input(&sha1_context, (const uint8 *) message, SCRAMBLE_LENGTH);
  mysql_sha1_input(&sha1_context, hash_stage2, SHA1_HASH_SIZE);
  /* xor allows 'from' and 'to' overlap: lets take advantage of it */
  mysql_sha1_result(&sha1_context, (uint8 *) to);
  my_crypt(to, (const uchar *) to, hash_stage1, SCRAMBLE_LENGTH);
}


void get_hash_stage1(const char *scramble_arg, const char *message,
               const uint8 *hash_stage2, uint8 *hash_stage1)
{
  SHA1_CONTEXT sha1_context;

  mysql_sha1_reset(&sha1_context);
  /* create key to encrypt scramble */
  mysql_sha1_input(&sha1_context, (const uint8 *) message, SCRAMBLE_LENGTH);
  mysql_sha1_input(&sha1_context, hash_stage2, SHA1_HASH_SIZE);
  mysql_sha1_result(&sha1_context, hash_stage1);
  /* encrypt scramble */
    my_crypt((char *) hash_stage1, hash_stage1, (const uchar *) scramble_arg, SCRAMBLE_LENGTH);
}




void get_salt_from_password(uint8 *hash_stage2, const char *password)
{
  hex2octet(hash_stage2, password+1 /* skip '*' */, SHA1_HASH_SIZE * 2);
}


/*
    Generate string of printable random characters of requested length
  SYNOPSIS
    create_random_string()
    to       OUT   buffer for generation; must be at least length+1 bytes
                   long; result string is always null-terminated
    length   IN    how many random characters to put in buffer
    rand_st  INOUT structure used for number generation
*/

void create_random_string(char *to, uint length, struct rand_struct *rand_st)
{
  char *end= to + length;
  /* Use pointer arithmetics as it is faster way to do so. */
  for (; to < end; to++)
    *to= (char) (my_rnd(rand_st)*94+33);
  *to= '\0';
}

