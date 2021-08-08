#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <sys/time.h>

typedef struct _rule
{
  int num;
  int sa1, sa2, sa3, sa4, slen;
  int da1, da2, da3, da4, dlen;
  int sp1, sp2, dp1, dp2;
  char proto[7];
  char Data[11];
} RULE;

typedef struct _pkt
{
  int num;
  int sa1, sa2, sa3, sa4;
  int da1, da2, da3, da4;
  int sp, dp;
  char proto[7];
  char Data[101];
} PACKET;

int numrules = 10, numpkts = 30;
RULE *RULE_ARR;
PACKET *PKT_ARR;
char *protocols[3] = {"tcp", "udp", "icmp"};
FILE *fp;
FILE *fppkt;

char GenChar()
{
  double f;
  int i; 

  f = drand48();

  if (f < 0.02)
    return 32;			/* Space */
  if (f < 0.43)
    return (65 + random()%26);	/* 'A' - 'Z' */
  if (f < 0.88)
    return (97 + random()%26);	/* 'a' - 'z' */
  else
    return (48 + random()% 10); /* '0' - '9' */

}

void print_src_addr_rule (FILE *fp, int a1, int  a2, int  a3, int  a4, int len)
{
  fprintf(fp,"SRC IP ADDR: %d.%d.%d.%d/%d\n", 
		  a1, a2, a3, a4, len); 
}

void print_src_addr_pkt (FILE *fp, int a1, int  a2, int  a3, int  a4)
{
  fprintf(fp,"SRC IP ADDR: %d.%d.%d.%d\n", 
		  a1, a2, a3, a4); 
}

void print_dest_addr_rule (FILE *fp, int a1, int a2, int a3, int a4, int  len)
{
  fprintf(fp,"DEST IP ADDR: %d.%d.%d.%d/%d\n", 
		  a1, a2, a3, a4, len); 
}

void print_dest_addr_pkt (FILE *fp, int a1, int a2, int a3, int a4)
{
  fprintf(fp,"DEST IP ADDR: %d.%d.%d.%d\n", 
		  a1, a2, a3, a4); 
}

int main(int argc, char **argv)
{
  int rulenum;
  int a1, a2, a3, a4, len;
  char rulefile[81];
  char pktfile[81];
  struct timeval tp;
  int p1, p2, temp, pktnum, pkts_rule, k; 
  char PktData[101];

  if (argc < 4)
    {
      fprintf(stdout,"Usage: %s numruls rulefile pktfile\n", argv[0]);
      exit(-1);
    }

  numrules = atoi(argv[1]);
  RULE_ARR = (RULE *) calloc(numrules+1, sizeof(RULE));

  strncpy(rulefile, argv[2], 80);
  fp = fopen(rulefile,"w");

  //  numpkts = atoi(argv[3]);
  // PKT_ARR = (PACKET *) calloc(numpkts+1, sizeof(PACKET));

  strncpy(pktfile, argv[3], 80);
  fppkt = fopen(pktfile,"w");

  gettimeofday(&tp, NULL);
  srandom(tp.tv_usec);
  srand48(tp.tv_sec);

  for (rulenum = 1; rulenum <= numrules; rulenum++)
    {
      fprintf(fp,"BEGIN\n");
      RULE_ARR[rulenum].num = rulenum;
      fprintf(fp,"NUM: %d\n", RULE_ARR[rulenum].num);

      /* SRC ADDRESS */
      temp = random() % 5; /* Generate some rules with any address spec. */
      if (temp == 0)
	{
	  RULE_ARR[rulenum].sa1 = 0;
	  RULE_ARR[rulenum].sa2 = 0;
	  RULE_ARR[rulenum].sa3 = 0;
	  RULE_ARR[rulenum].sa4 = 0;
	  RULE_ARR[rulenum].slen = 0;
	}
      else
	{
	  a1 = 1 + random()%254; /* 255 is not generated */
	  while (a1 == 127) 	
	    a1 = 1 + random()%254; /* 127 is Ignored */

	  if ((a1 >= 1) && (a1 <= 126))
	    {
	      RULE_ARR[rulenum].sa1 = a1;
	      RULE_ARR[rulenum].sa2 = 0;
	      RULE_ARR[rulenum].sa3 = 0;
	      RULE_ARR[rulenum].sa4 = 0;
	      RULE_ARR[rulenum].slen = 8;
	    }

	  if ((a1 >= 128) && (a1 <= 191))
	    {
	      a2 = (8 + random()%8 )*16; 

	      RULE_ARR[rulenum].sa1 = a1;
	      RULE_ARR[rulenum].sa2 = a2;
	      RULE_ARR[rulenum].sa3 = 0;
	      RULE_ARR[rulenum].sa4 = 0;
	      RULE_ARR[rulenum].slen = 12;
	    }

	  if ((a1 >= 192) && (a1 <= 254))
	    {
	      a2 = 1 + random()%254; /* 255 is not generated */
	      a3 = (8 + random()%8 )*16; 

	      RULE_ARR[rulenum].sa1 = a1;
	      RULE_ARR[rulenum].sa2 = a2;
	      RULE_ARR[rulenum].sa3 = a3;
	      RULE_ARR[rulenum].sa4 = 0;
	      RULE_ARR[rulenum].slen = 20;
	    }
	}
      
      print_src_addr_rule(fp, RULE_ARR[rulenum].sa1,
		     RULE_ARR[rulenum].sa2,
		     RULE_ARR[rulenum].sa3,
		     RULE_ARR[rulenum].sa4,
		     RULE_ARR[rulenum].slen);

      /* DEST ADDRESS */
      temp = random() % 5; /* Generate some rules with any address spec. */
      if (temp == 0)
	{
	  RULE_ARR[rulenum].da1 = 0;
	  RULE_ARR[rulenum].da2 = 0;
	  RULE_ARR[rulenum].da3 = 0;
	  RULE_ARR[rulenum].da4 = 0;
	  RULE_ARR[rulenum].dlen = 0;
	}
      else
	{
	  a1 = 1 + random()%254; /* 255 is not generated */
	  while (a1 == 127) 	
	    a1 = 1 + random()%254; /* 127 is Ignored */

	  if ((a1 >= 1) && (a1 <= 126))
	    {
	      RULE_ARR[rulenum].da1 = a1;
	      RULE_ARR[rulenum].da2 = 0;
	      RULE_ARR[rulenum].da3 = 0;
	      RULE_ARR[rulenum].da4 = 0;
	      RULE_ARR[rulenum].dlen = 8;
	    }

	  if ((a1 >= 128) && (a1 <= 191))
	    {
	      a2 = (8 + random()%8 )*16; 

	      RULE_ARR[rulenum].da1 = a1;
	      RULE_ARR[rulenum].da2 = a2;
	      RULE_ARR[rulenum].da3 = 0;
	      RULE_ARR[rulenum].da4 = 0;
	      RULE_ARR[rulenum].dlen = 12;
	    }

	  if ((a1 >= 192) && (a1 <= 254))
	    {
	      a2 = 1 + random()%254; /* 255 is not generated */
	      a3 = (8 + random()%8 )*16; 

	      RULE_ARR[rulenum].da1 = a1;
	      RULE_ARR[rulenum].da2 = a2;
	      RULE_ARR[rulenum].da3 = a3;
	      RULE_ARR[rulenum].da4 = 0;
	      RULE_ARR[rulenum].dlen = 20;
	    }
	}
      
      print_dest_addr_rule(fp, RULE_ARR[rulenum].da1,
		     RULE_ARR[rulenum].da2,
		     RULE_ARR[rulenum].da3,
		     RULE_ARR[rulenum].da4,
		     RULE_ARR[rulenum].dlen);

      /* SRC PORT */
      temp = random() % 3;	/* Generate some rules with any port spec. */
      if (temp == 0) 		/* with probability of 1/3. */
	p1 = 0;
      else 
	p1 = random() % 65536;
      if ((p1 == 0) || (p1 == 65535)) p2 = p1;
      else 
	{
	  p2 = random() % 65536;
	  while (p2 < p1)
	    p2 = random() % 65536;
	}
      RULE_ARR[rulenum].sp1 = p1;
      RULE_ARR[rulenum].sp2 = p2;
      fprintf(fp,"SRC PORT: %d-%d\n", 
	      RULE_ARR[rulenum].sp1, RULE_ARR[rulenum].sp2);

      /* DEST PORT */
      temp = random() % 3;	/* Generate some rules with any port spec. */
      if (temp == 0) 		/* with probability of 1/3. */
	p1 = 0;
      else 
	p1 = random() % 65536;
      if ((p1 == 0) || (p1 == 65535)) p2 = p1;
      else 
	{
	  p2 = random() % 65536;
	  while (p2 < p1)
	    p2 = random() % 65536;
	}
      RULE_ARR[rulenum].dp1 = p1;
      RULE_ARR[rulenum].dp2 = p2;
      fprintf(fp,"DEST PORT: %d-%d\n", 
	      RULE_ARR[rulenum].dp1, RULE_ARR[rulenum].dp2);

      /* PROTOCOL */      
      temp = random() % 3;
      strncpy(RULE_ARR[rulenum].proto, protocols[temp],6);
      fprintf(fp,"PROTOCOL: %s\n", RULE_ARR[rulenum].proto);

      int i;
      for (i = 0; i < 10; i++)
	RULE_ARR[rulenum].Data[i] = GenChar();
      RULE_ARR[rulenum].Data[10] = '\0';
      fprintf(fp,"DATA: %s\n", RULE_ARR[rulenum].Data);

      fprintf(fp,"END\n");
    }

  pktnum = 0;
  for (rulenum = 1; rulenum <= numrules; rulenum++)
    {
      pkts_rule = 2 + random() % 5;
      fprintf(stdout,"RULE: %d\n", rulenum);
      print_src_addr_rule(stdout, RULE_ARR[rulenum].sa1,
		     RULE_ARR[rulenum].sa2,
		     RULE_ARR[rulenum].sa3,
		     RULE_ARR[rulenum].sa4,
		     RULE_ARR[rulenum].slen);
 
      for (k = 0; k < pkts_rule; k++)
	{
	  pktnum++;
	  fprintf(stdout,"\t\t\tPKT: %d\n", pktnum);
	  fprintf(fppkt,"BEGIN\n");
	  fprintf(fppkt,"NUM: %d\n", pktnum);
      
	  if (RULE_ARR[rulenum].slen == 0)
	    {
	      a1 = 1 + random() % 254;
	      a2 = 1 + random() % 254;
	      a3 = 1 + random() % 254;
	      a4 = 1 + random() % 254;
	    }
	  if (RULE_ARR[rulenum].slen == 8)
	    {
	      a1 = RULE_ARR[rulenum].sa1;
	      a2 = 1 + random() % 254;
	      a3 = 1 + random() % 254;
	      a4 = 1 + random() % 254;
	    } /* address of length 8 */
	  if (RULE_ARR[rulenum].slen == 12)
	    {
	      a1 = RULE_ARR[rulenum].sa1;
	      a2 = RULE_ARR[rulenum].sa2 + random() % 16;
	      a3 = 1 + random() % 254;
	      a4 = 1 + random() % 254;
	    }/* address of length 12 */
	  if (RULE_ARR[rulenum].slen == 20)
	    {
	      a1 = RULE_ARR[rulenum].sa1;
	      a2 = RULE_ARR[rulenum].sa2;
	      a3 = RULE_ARR[rulenum].sa3 + random() % 16;
	      a4 = 1 + random() % 254;
	    }/* address of length 20 */

	  print_src_addr_pkt(fppkt, a1, a2, a3, a4);
	  //	  fprintf(stdout,"\t\t\t");
	  //	  print_src_addr_pkt(stdout, a1, a2, a3, a4);

	  if (RULE_ARR[rulenum].dlen == 0)
	    {
	      a1 = 1 + random() % 254;
	      a2 = 1 + random() % 254;
	      a3 = 1 + random() % 254;
	      a4 = 1 + random() % 254;
	    }
	  if (RULE_ARR[rulenum].dlen == 8)
	    {
	      a1 = RULE_ARR[rulenum].da1;
	      a2 = 1 + random() % 254;
	      a3 = 1 + random() % 254;
	      a4 = 1 + random() % 254;
	    } /* address of length 8 */
	  if (RULE_ARR[rulenum].dlen == 12)
	    {
	      a1 = RULE_ARR[rulenum].da1;
	      a2 = RULE_ARR[rulenum].da2 + random() % 16;
	      a3 = 1 + random() % 254;
	      a4 = 1 + random() % 254;
	    }/* address of length 12 */
	  if (RULE_ARR[rulenum].dlen == 20)
	    {
	      a1 = RULE_ARR[rulenum].da1;
	      a2 = RULE_ARR[rulenum].da2;
	      a3 = RULE_ARR[rulenum].da3 + random() % 16;
	      a4 = 1 + random() % 254;
	    }/* address of length 20 */

	  print_dest_addr_pkt(fppkt, a1, a2, a3, a4);
	  //	  fprintf(stdout,"\t\t\t");
	  //	  print_src_addr_pkt(stdout, a1, a2, a3, a4);

	  if (RULE_ARR[rulenum].sp1 == 0)
	    p1 = 1 + random() % 65535;
	  else
	    {
	      p1 = RULE_ARR[rulenum].sp1 +
		random()%(RULE_ARR[rulenum].sp2 - RULE_ARR[rulenum].sp1 + 1);
	    }

	  fprintf(fppkt,"SRC PORT: %d\n", p1);

	  if (RULE_ARR[rulenum].dp1 == 0)
	    p1 = 1 + random() % 65535;
	  else
	    {
	      temp = random() % 5;
	      if (temp > 0)
		p1 = RULE_ARR[rulenum].dp1 +
		  random()%(RULE_ARR[rulenum].dp2 - RULE_ARR[rulenum].dp1 + 1);
	      else		/* Deliberately Out of range */
		p1 = 65536 + (random() % 65536);
	    }

	  fprintf(fppkt,"DEST PORT: %d\n", p1);

	  /* PROTOCOL */      
	  temp = random() % 4;
	  if (temp > 0)
	    fprintf(fppkt,"PROTOCOL: %s\n", RULE_ARR[rulenum].proto);
	  else
	    fprintf(fppkt,"PROTOCOL: %s\n", protocols[random()%3]);

	  int i, m;
	  for (i = 0; i < 100; i++)
	    PktData[i] = GenChar();
	  PktData[100] = '\0';

	  if (drand48() > 0.2)	/* Include string in packet from rule */
	    {			/* 80% of the time */
	      m = random() % 90; /* Random starting point to add string  */
	      /* strncpy 10 bytes from rule to replace this with prob. 0.8 */
	      for (int j = 0; j < 10; j++)
		PktData[m+j] = RULE_ARR[rulenum].Data[j];
	      fprintf(stdout,"%s; %s\n", PktData, RULE_ARR[rulenum].Data);
	    }

	  fprintf(fppkt,"DATA: %s\n", PktData);

	  fprintf(fppkt,"END\n");
	} /* End per-pkt */
      
    }	  /* End per-rule */
}	  /* End main */
