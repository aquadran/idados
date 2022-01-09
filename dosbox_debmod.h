#ifndef __DOSBOX_DEBUGGER_MODULE__
#define __DOSBOX_DEBUGGER_MODULE__


#include "dosbox.h"
#include "mem.h"

#include <algorithm>
#include <vector>
#include <map>
#include <set>
#include <deque>

#include "pc_debmod.h"

typedef std::set<ea_t> easet_t;         // set of addresses

// image information
struct image_info_t
{
  qstring name;
};

typedef std::map<ea_t, image_info_t> images_t; // key: codeaddr

struct bpt_info_t
{
  int bid;              // breakpoint id (from TRK)
  int cnt;              // number of times ida kernel added the bpt
  bpt_info_t(int b, int c) : bid(b), cnt(c) {}
};

typedef std::map<ea_t, bpt_info_t> bpts_t;

// thread information
struct thread_info_t
{
};

class dosbox_debmod_t: public pc_debmod_t
{
  typedef pc_debmod_t inherited;

  ea_t entry_point;
  ea_t app_base;
  ea_t stack;

  void cleanup(void);
  void create_process_start_event(const char *path);

public:

  int dosbox_step_ret;

  // debugged process information
  eventlist_t events;              // Pending events
  bool exited;                     // Process has exited

  bpts_t bpts;                     // breakpoint list

  static bool reuse_broken_connections;

  dosbox_debmod_t();
  ~dosbox_debmod_t();

  virtual void idaapi dbg_set_debugging(bool _debug_debugger);
  virtual int idaapi dbg_init(void);
  virtual void idaapi dbg_term(void);
  virtual int idaapi dbg_get_processes(procinfo_vec_t *procs);
  virtual int idaapi dbg_detach_process(void);
  virtual int idaapi dbg_start_process(const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32);
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_ms);
  virtual int idaapi dbg_attach_process(pid_t process_id, int event_id, int flags);
  virtual int idaapi dbg_prepare_to_pause_process(void);
  virtual int idaapi dbg_exit_process(void);
  virtual int idaapi dbg_continue_after_event(const debug_event_t *event);
  virtual void idaapi dbg_set_exception_info(const exception_info_t *info, int qty);
  virtual void idaapi dbg_stopped_at_debug_event(void);
  virtual int idaapi dbg_thread_suspend(thid_t thread_id);
  virtual int idaapi dbg_thread_continue(thid_t thread_id);
  virtual int idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod);
  virtual int idaapi dbg_read_registers(thid_t thread_id,
        int clsmask,
        regval_t *values);
  virtual int idaapi dbg_write_register(thid_t thread_id,
        int reg_idx,
        const regval_t *value);
  virtual int idaapi dbg_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value);
  virtual int idaapi dbg_get_memory_info(meminfo_vec_t &areas);
  virtual int idaapi dbg_get_scattered_image(scattered_image_t &si, ea_t base);
  virtual bool idaapi dbg_get_image_uuid(bytevec_t *uuid, ea_t base);
  virtual ea_t idaapi dbg_get_segm_start(ea_t base, const qstring &segname);
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size);
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size);
  virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len);
  virtual int idaapi dbg_add_bpt(bpttype_t type, ea_t ea, int len);
  virtual int idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len);
//  virtual int idaapi dbg_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel);
//  virtual int idaapi dbg_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds);
//  virtual int idaapi dbg_eval_lowcnd(thid_t tid, ea_t ea);
  virtual int idaapi dbg_open_file(const char *file, uint64 *fsize, bool readonly);
  virtual void idaapi dbg_close_file(int fn);
  virtual ssize_t idaapi dbg_read_file(int fn, qoff64_t off, void *buf, size_t size);
  virtual ssize_t idaapi dbg_write_file(int fn, qoff64_t off, const void *buf, size_t size);
//  virtual int idaapi handle_ioctl(int fn, const void *buf, size_t size, void **outbuf, ssize_t *outsize);
  virtual int idaapi get_system_specific_errno(void) const;
//  virtual bool idaapi dbg_update_call_stack(thid_t, call_stack_t *);
/*  virtual ea_t idaapi dbg_appcall(
        ea_t func_ea,
        thid_t tid,
        int stkarg_nbytes,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int flags);*/
//  virtual int idaapi dbg_cleanup_appcall(thid_t tid);
//  virtual int get_regidx(const char *, int *) { INTERR(30116); }
//  virtual int idaapi dbg_rexec(const char *cmdline);

  bool idaapi close_remote(void);
  bool idaapi open_remote(const char * /*hostname*/, int port_number, const char * /*password*/);

  bool hit_breakpoint(PhysPt addr);
};

debmod_t *create_debug_session();
bool term_subsystem();
bool init_subsystem();

#define DOSBOX_DEBUGGER_NODE "$ dosbox debugger"  // netnode name to save memory region
                                              // information
#define MEMREG_TAG 'R'                        // blob tag

#endif
