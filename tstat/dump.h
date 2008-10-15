#ifndef DUMP_H_HDR
#define DUMP_H_HDR
//char dump_conf_fname[200];
void dump_init          (void);
void dump_flow_stat     (struct ip *pip, void *pproto, int tproto, 
                         void *pdir, int dir, void *hdr, void *plast);
void dump_flush         (Bool trace_completed);
void dump_create_outdir (char * basedir);
//void dump_restart       (void);
void dump_parse_ini_arg (char *param_name, int param_value);
#endif
