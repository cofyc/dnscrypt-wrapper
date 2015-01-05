/* dnsmasq is Copyright (c) 2000-2012 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * This file is modified from dnsmasq/src/rfc1035.c.
 */

#include "rfc1035.h"

#define CHECK_LEN(header, pp, plen, len) \
    ((size_t)((pp) - (unsigned char *)(header) + (len)) <= (plen))

#define ADD_RDLEN(header, pp, plen, len) \
  (!CHECK_LEN(header, pp, plen, len) ? 0 : (((pp) += (len)), 1))

int
extract_name(struct dns_header *header, size_t plen, unsigned char **pp, char
        *name, int isExtract, int extrabytes)
{
  unsigned char *cp = (unsigned char *)name, *p = *pp, *p1 = NULL;
  unsigned int j, l, hops = 0;
  int retvalue = 1;
  
  if (isExtract)
    *cp = 0;

  while (1)
    { 
      unsigned int label_type;

      if (!CHECK_LEN(header, p, plen, 1))
	return 0;
      
      if ((l = *p++) == 0) 
	/* end marker */
	{
	  /* check that there are the correct no of bytes after the name */
	  if (!CHECK_LEN(header, p, plen, extrabytes))
	    return 0;
	  
	  if (isExtract)
	    {
	      if (cp != (unsigned char *)name)
		cp--;
	      *cp = 0; /* terminate: lose final period */
	    }
	  else if (*cp != 0)
	    retvalue = 2;
	  
	  if (p1) /* we jumped via compression */
	    *pp = p1;
	  else
	    *pp = p;
	  
	  return retvalue;
	}

      label_type = l & 0xc0;
      
      if (label_type == 0xc0) /* pointer */
	{ 
	  if (!CHECK_LEN(header, p, plen, 1))
	    return 0;
	      
	  /* get offset */
	  l = (l&0x3f) << 8;
	  l |= *p++;
	  
	  if (!p1) /* first jump, save location to go back to */
	    p1 = p;
	      
	  hops++; /* break malicious infinite loops */
	  if (hops > 255)
	    return 0;
	  
	  p = l + (unsigned char *)header;
	}
      else if (label_type == 0x80)
	return 0; /* reserved */
      else if (label_type == 0x40)
	{ /* ELT */
	  unsigned int count, digs;
	  
	  if ((l & 0x3f) != 1)
	    return 0; /* we only understand bitstrings */

	  if (!isExtract)
	    return 0; /* Cannot compare bitsrings */
	  
	  count = *p++;
	  if (count == 0)
	    count = 256;
	  digs = ((count-1)>>2)+1;
	  
	  /* output is \[x<hex>/siz]. which is digs+9 chars */
	  if (cp - (unsigned char *)name + digs + 9 >= MAXDNAME)
	    return 0;
	  if (!CHECK_LEN(header, p, plen, (count-1)>>3))
	    return 0;

	  *cp++ = '\\';
	  *cp++ = '[';
	  *cp++ = 'x';
	  for (j=0; j<digs; j++)
	    {
	      unsigned int dig;
	      if (j%2 == 0)
		dig = *p >> 4;
	      else
		dig = *p++ & 0x0f;
	      
	      *cp++ = dig < 10 ? dig + '0' : dig + 'A' - 10;
	    } 
	  cp += sprintf((char *)cp, "/%d]", count);
	  /* do this here to overwrite the zero char from sprintf */
	  *cp++ = '.';
	}
      else 
	{ /* label_type = 0 -> label. */
	  if (cp - (unsigned char *)name + l + 1 >= MAXDNAME)
	    return 0;
	  if (!CHECK_LEN(header, p, plen, l))
	    return 0;
	  
	  for(j=0; j<l; j++, p++)
	    if (isExtract)
	      {
		unsigned char c = *p;
		if (isascii(c) && !iscntrl(c) && c != '.')
		  *cp++ = *p;
		else
		  return 0;
	      }
	    else 
	      {
		unsigned char c1 = *cp, c2 = *p;
		
		if (c1 == 0)
		  retvalue = 2;
		else 
		  {
		    cp++;
		    if (c1 >= 'A' && c1 <= 'Z')
		      c1 += 'a' - 'A';
		    if (c2 >= 'A' && c2 <= 'Z')
		      c2 += 'a' - 'A';
		    
		    if (c1 != c2)
		      retvalue =  2;
		  }
	      }
	  
	  if (isExtract)
	    *cp++ = '.';
	  else if (*cp != 0 && *cp++ != '.')
	    retvalue = 2;
	}
    }
}

/* Hash the question section. This is used to safely detect query
   retransmision and to detect answers to questions we didn't ask, which 
   might be poisoning attacks. Note that we decode the name rather 
   than hash the raw bytes, since replies might be compressed differently. 
   We ignore case in the names for the same reason. Return all-ones
   if there is not question section. */
int
questions_hash(uint64_t *hash, struct dns_header *header, size_t plen, char *name, const unsigned char key[crypto_shorthash_KEYBYTES])
{
  unsigned char qb[MAXDNAME + 4];
  unsigned char *p = (unsigned char *)(header+1);
  size_t name_len;

  if (ntohs(header->qdcount) != 1 ||
      !extract_name(header, plen, &p, name, 1, 4) ||
      (name_len = strlen(name)) > (sizeof qb - 4)) {
      return -1;
  }
  memcpy(qb, name, name_len);
  memcpy(qb + name_len, p, 4);
  crypto_shorthash((unsigned char *) hash, qb, name_len + 4ULL, key);

  return 0;
}

static unsigned char *skip_name(unsigned char *ansp, struct dns_header *header, size_t plen, int extrabytes)
{
  while(1)
    {
      unsigned int label_type;

      if (!CHECK_LEN(header, ansp, plen, 1))
    return NULL;

      label_type = (*ansp) & 0xc0;

      if (label_type == 0xc0)
    {
      /* pointer for compression. */
      ansp += 2;
      break;
    }
      else if (label_type == 0x80)
    return NULL; /* reserved */
      else if (label_type == 0x40)
    {
      /* Extended label type */
      unsigned int count;

      if (!CHECK_LEN(header, ansp, plen, 2))
        return NULL;

    if (((*ansp++) & 0x3f) != 1)
        return NULL; /* we only understand bitstrings */

      count = *(ansp++); /* Bits in bitstring */

      if (count == 0) /* count == 0 means 256 bits */
        ansp += 32;
      else
        ansp += ((count-1)>>3)+1;
    }
      else
    { /* label type == 0 Bottom six bits is length */
      unsigned int len = (*ansp++) & 0x3f;

      if (!ADD_RDLEN(header, ansp, plen, len))
        return NULL;

      if (len == 0)
        break; /* zero length label marks the end. */
    }
    }

  if (!CHECK_LEN(header, ansp, plen, extrabytes))
    return NULL;

  return ansp;
}


unsigned char *
skip_questions(struct dns_header *header, size_t plen)
{
  int q;
  unsigned char *ansp = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      if (!(ansp = skip_name(ansp, header, plen, 4)))
    return NULL;
      ansp += 4; /* class and type */
    }

  return ansp;
}

unsigned char *
do_rfc1035_name(unsigned char *p, char *sval)
{   
  int j;

  while (sval && *sval)
    {
      unsigned char *cp = p++;
      for (j = 0; *sval && (*sval != '.'); sval++, j++)
    *p++ = *sval;
      *cp  = j;
      if (*sval)
    sval++;
    } 
  return p;
} 

int
add_resource_record(struct dns_header *header, unsigned int nameoffset, unsigned char **pp, 
			       unsigned long ttl, unsigned int *offset, unsigned short type, unsigned short class, char *format, ...)
{
  va_list ap;
  unsigned char *sav, *p = *pp;
  int j;
  unsigned short usval;
  long lval;
  char *sval;


  PUTSHORT(nameoffset | 0xc000, p);
  PUTSHORT(type, p);
  PUTSHORT(class, p);
  PUTLONG(ttl, p);      /* TTL */

  sav = p;              /* Save pointer to RDLength field */
  PUTSHORT(0, p);       /* Placeholder RDLength */

  va_start(ap, format);   /* make ap point to 1st unamed argument */
  
  for (; *format; format++)
    switch (*format)
      {
#ifdef HAVE_IPV6
      case '6':
	sval = va_arg(ap, char *); 
	memcpy(p, sval, IN6ADDRSZ);
	p += IN6ADDRSZ;
	break;
#endif
	
      case '4':
	sval = va_arg(ap, char *); 
	memcpy(p, sval, INADDRSZ);
	p += INADDRSZ;
	break;
	
      case 's':
	usval = va_arg(ap, int);
	PUTSHORT(usval, p);
	break;
	
      case 'l':
	lval = va_arg(ap, long);
	PUTLONG(lval, p);
	break;
	
      case 'd':
	/* get domain-name answer arg and store it in RDATA field */
	if (offset)
	  *offset = p - (unsigned char *)header;
	p = do_rfc1035_name(p, va_arg(ap, char *));
	*p++ = 0;
	break;
	
      case 't':
	usval = va_arg(ap, int);
	sval = va_arg(ap, char *);
	if (usval != 0)
	  memcpy(p, sval, usval);
	p += usval;
	break;

      case 'z':
	sval = va_arg(ap, char *);
	usval = sval ? strlen(sval) : 0;
	if (usval > 255)
	  usval = 255;
	*p++ = (unsigned char)usval;
	memcpy(p, sval, usval);
	p += usval;
	break;
      }

  va_end(ap);	/* clean up variable argument pointer */
  
  j = p - sav - 2;
  PUTSHORT(j, sav);     /* Now, store real RDLength */
  
  *pp = p;
  return 1;
}
