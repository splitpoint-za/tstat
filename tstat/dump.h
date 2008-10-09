#ifndef DUMP_H_HDR
#define DUMP_H_HDR
char dump_conf_fname[200];
void dump_init          (void);
void dump_flow_stat     (struct ip *pip, void *pproto, int tproto, 
                         void *pdir, int dir, void *hdr, void *plast);
void dump_flush         (void);
void dump_create_outdir (char * basedir);
#endif
