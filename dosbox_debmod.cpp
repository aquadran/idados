/*

*/
#include <ida.hpp>
#include <err.h>
#include <idp.hpp>
#include <diskio.hpp>
#include <segment.hpp>
#include "consts.h"
#include "dosbox_debmod.h"

#include "dosbox.h"
#include "cpu.h"
#include "mem.h"


inline ea_t find_app_base();

//defined in debug.cpp
Bit32u GetAddress(Bit16u seg, Bit32u offset);
bool DEBUG_AddBreakPoint(Bit32u address, bool once);
bool DEBUG_AddMemBreakPoint(Bit32u address);
bool DEBUG_DelBreakPoint(PhysPt address);
int DEBUG_Continue(void);
Bits DEBUG_RemoteStep(void);

//server.cpp
void idados_running();
void idados_stopped();

extern debugger_t debugger;
bool debug_debugger;

//--------------------------------------------------------------------------
// Initialize static members
// TODO: Can we support this?
bool dosbox_debmod_t::reuse_broken_connections = false;

//--------------------------------------------------------------------------
dosbox_debmod_t::dosbox_debmod_t(void)
{
}

//--------------------------------------------------------------------------
dosbox_debmod_t::~dosbox_debmod_t(void)
{
}

//--------------------------------------------------------------------------
bool idaapi dosbox_debmod_t::close_remote(void)
{
    return true;
}

//--------------------------------------------------------------------------
bool idaapi dosbox_debmod_t::open_remote(const char * /*hostname*/, int port_number, const char * /*password*/)
{
    return true;
}

//--------------------------------------------------------------------------
void dosbox_debmod_t::cleanup(void)
{
  inherited::cleanup();
  events.clear();
  bpts.clear();
  exited = false;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_add_bpt(bpttype_t type, ea_t ea, int len)
{
  bpts_t::iterator p = bpts.find(ea);
  if ( p != bpts.end() )
  {
    // already has a bpt at the specified address
    // unfortunately the kernel may ask to set several bpts at the same addr
    // FIXME: Handle 'type' here too
    p->second.cnt++;
    return 1;
  }

 printf("new breakpoint at 0x%x.\n", ea);

 //ea += r_debug.base;
 switch(type)
 {
   case BPT_EXEC :
   case BPT_SOFT : DEBUG_AddBreakPoint((Bit32u)ea, false); break;
   case BPT_RDWR :
   case BPT_WRITE : DEBUG_AddMemBreakPoint((Bit32u)ea); break;
   case BPT_READ :
     // Unsupported
     return 0; // failed
 }

  bpts.insert(std::make_pair(ea, bpt_info_t(1, 1)));

  return 1; // ok
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_del_bpt(bpttype_t /*type*/, ea_t ea, const uchar * /*orig_bytes*/, int /*len*/)
{
  // FIXME: Handle 'type' argument!
  bpts_t::iterator p = bpts.find(ea);
  if ( p == bpts.end() )
    return 0; // failed
  if ( --p->second.cnt == 0 )
  {
    int bid = p->second.bid;
    bpts.erase(p);

    DEBUG_DelBreakPoint((PhysPt)ea);
  }
  return 1; // ok
}

//--------------------------------------------------------------------------
void idaapi dosbox_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = ::debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_init(void)
{
  cleanup();
  return 1;
}

//--------------------------------------------------------------------------
void idaapi dosbox_debmod_t::dbg_term(void)
{
}

int idaapi dosbox_debmod_t::dbg_get_processes(procinfo_vec_t *procs)
{
    return 0;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_detach_process(void)
{
  return 0; // can not detach
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_start_process(
  const char *path,
  const char *args,
  const char * /*startdir*/,
  int /* flags */,
  const char * /*input_path*/,
  uint32 /* input_file_crc32 */)
{

  entry_point = (ea_t)GetAddress(SegValue(cs), reg_eip);
  printf("entry_point = %x\n", entry_point);
  app_base = find_app_base();
  printf("app_base = %x\n", app_base);
  stack = SegValue(ss);
  printf("name %s \n",path);
  create_process_start_event(path);
  return 1;
}

//--------------------------------------------------------------------------
void dosbox_debmod_t::create_process_start_event(const char *path)
{
  ea_t base;
  debug_event_t ev;

  base = find_app_base();

  ev.eid = PROCESS_START;
  ev.pid = NO_PROCESS;//pi.pid;
  ev.tid = NO_PROCESS;//pi.tid;
  ev.ea = BADADDR;
  ev.handled = false;
  qstrncpy(ev.modinfo.name, path, sizeof(ev.modinfo.name));
  ev.modinfo.base = app_base + 0x100; //base + PSP //entry_point; //pi.codeaddr;
  ev.modinfo.size = 0;
  ev.modinfo.rebase_to = app_base + 0x100; //base + PSP //entry_point;
  events.enqueue(ev, IN_BACK);
}

//--------------------------------------------------------------------------
gdecode_t idaapi dosbox_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  if ( event == NULL )
    return GDE_NO_EVENT;

  while ( true )
  {
    // are there any pending events?
    if ( events.retrieve(event) )
    {
      debdeb("GDE: %s\n", debug_event_str(event));
      return GDE_ONE_EVENT;
    }
    // no pending events, check the target
    if ( events.empty() )
      break;
  }

  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_attach_process(pid_t process_id, int event_id, int flags)
{
  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_prepare_to_pause_process(void)
{
  debug_event_t ev;

  ev.eid = NO_EVENT;
  ev.pid = NO_PROCESS;
  ev.tid = NO_PROCESS;
  ev.bpt.hea = BADADDR; //addr; //BADADDR; //r_debug.base - addr; //BADADDR; //addr;//r_debug.base - addr;
  ev.bpt.kea = BADADDR;//(ea_t)reg_eip;
  ev.ea = (ea_t)GetAddress(SegValue(cs), reg_eip);
  ev.handled = true;
  ev.exc.code = 0;
  ev.exc.can_cont = true;
  ev.exc.ea = BADADDR;

  events.enqueue(ev, IN_BACK);

  idados_stopped();

  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_exit_process(void)
{
  debug_event_t ev;

  ev.eid = PROCESS_EXIT;
  ev.tid = NO_PROCESS;
  ev.pid = NO_PROCESS;
  ev.ea = BADADDR;
  ev.handled = false;
  ev.exit_code = 0;

  events.enqueue(ev, IN_BACK);

  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  if ( exited
    || event->eid == LIBRARY_UNLOAD   // TRK doesn't need this?
    || event->eid == THREAD_START     // fake event - btw, how do we detect thread creation?
    || event->eid == PROCESS_EXIT )   // After EXIT TRK does not accept 'continue'
  {
printf("bad event->eid\n");
    return 1;
  }

  // if there are pending events, do not resume the app
  // in fact, the whole debugger logic is flawed.
  // it must be ready for a bunch of events, process all of them
  // and only after that resume the whole application or part of it.
  // fixme: rewrite event handling in the debugger
  if ( !events.empty() )
  {
    printf("Events in the event queue.\n");
    return 1;
  }

  idados_running();
  return 1;
}

void idaapi dosbox_debmod_t::dbg_set_exception_info(const exception_info_t *table, int qty)
{
}

//--------------------------------------------------------------------------
void idaapi dosbox_debmod_t::dbg_stopped_at_debug_event(void)
{
    printf("GET HERE dbg_stopped_at_debug_event\n");
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_thread_suspend(thid_t tid)
{
  return 1; //trk.suspend_thread(pi.pid, tid);
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_thread_continue(thid_t tid)
{
  return 1; //trk.resume_thread(pi.pid, tid);
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return 0; // not supported

  dosbox_step_ret = DEBUG_RemoteStep(); //fixme step return.

  debug_event_t ev;
    ev.eid = STEP;
    ev.pid = NO_PROCESS;
    ev.tid = NO_PROCESS;
    ev.ea =(ea_t)GetAddress(SegValue(cs),reg_ip);
    ev.handled = false;

  events.enqueue(ev, IN_BACK);

  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  if ( (clsmask & X86_RC_GENERAL) != 0 ) {

  values[R_EAX   ].ival = (uint64)reg_eax;
  values[R_EBX   ].ival = (uint64)reg_ebx;
  values[R_ECX   ].ival = (uint64)reg_ecx;
  values[R_EDX   ].ival = (uint64)reg_edx;//GetAddress(SegValue(ds), (ulong)reg_edx);//(ulong)reg_edx;
  values[R_ESI   ].ival = (uint64)reg_esi;
  values[R_EDI   ].ival = (uint64)reg_edi;
  values[R_EBP   ].ival = (uint64)reg_ebp;
  values[R_ESP   ].ival = (uint64)reg_esp;
  values[R_EIP   ].ival = (uint64)reg_eip;
//  values[R_ESP   ].ival = GetAddress(SegValue(ss), (Bit32u)reg_esp);
//  values[R_EIP   ].ival = GetAddress(SegValue(cs), (Bit32u)reg_eip);
  values[R_EFLAGS].ival = (uint64)reg_flags;

  }

  if ( (clsmask & X86_RC_SEGMENTS) != 0 ) {

  values[R_CS    ].ival = (uint64)SegValue(cs);
  values[R_DS    ].ival = (uint64)SegValue(ds);
  values[R_ES    ].ival = (uint64)SegValue(es);
  values[R_FS    ].ival = (uint64)SegValue(fs);
  values[R_GS    ].ival = (uint64)SegValue(gs);
  values[R_SS    ].ival = (uint64)SegValue(ss);

  }

  // TODO: clear registers for X86_RC_XMM, X86_RC_FPU, X86_RC_MMX

  printf("AX = %04x",(uint32)values[R_EAX   ].ival);
  printf(" BX = %04x",(uint32)values[R_EBX   ].ival);
  printf(" CX = %04x",(uint32)values[R_ECX   ].ival);
  printf(" DX = %04x\n",(uint32)values[R_EDX   ].ival);
  printf("SI = %04x",(uint32)values[R_ESI   ].ival);
  printf(" DI = %04x",(uint32)values[R_EDI   ].ival);
  printf(" BP = %04x",(uint32)values[R_EBP   ].ival);
  printf(" SP = %04x\n",(uint32)values[R_ESP   ].ival);
  printf("IP = %04x",(uint32)values[R_EIP   ].ival);
  printf(" Flags = %04x\n",(uint32)values[R_EFLAGS].ival);
  printf("CS = %04x",(uint32)values[R_CS    ].ival);
  printf(" SS = %04x",(uint32)values[R_SS    ].ival);
  printf(" DS = %04x",(uint32)values[R_DS    ].ival);
  printf(" ES = %04x\n",(uint32)values[R_ES    ].ival);
  printf("FS = %04x",(uint32)values[R_FS    ].ival);
  printf(" GS = %04x\n",(uint32)values[R_GS    ].ival);

  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  uint32 v = (uint32)value->ival;
  printf("write_reg R%d <- %08X\n", reg_idx, v);

  switch(reg_idx)
  {
    case R_EAX : reg_eax = value->ival; break;

    case R_EBX : reg_ebx = value->ival; break;
    case R_ECX : reg_ecx = value->ival; break;
    case R_EDX : reg_edx = value->ival; break;
    case R_ESI : reg_esi = value->ival; break;
    case R_EDI : reg_edi = value->ival; break;
    case R_EBP : reg_ebp = value->ival; break;
    case R_ESP : reg_esp = value->ival; break;
    //case R_EIP : reg_eip = value->ival; break;
    case R_EFLAGS : reg_flags = value->ival; break;

    case R_CS : SegSet16(cs, value->ival); break;
    case R_DS : SegSet16(ds, value->ival); break;
    case R_ES : SegSet16(es, value->ival); break;
    case R_FS : SegSet16(fs, value->ival); break;
    case R_GS : SegSet16(gs, value->ival); break;
    case R_SS : SegSet16(ss, value->ival); break;

    default : break;
  }

  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_get_memory_info(meminfo_vec_t &miv)
{
/*
   miv->start_ea = 0x0; //0;//r_debug.base; //(ea_t)GetAddress(0,0);
   miv->end_ea = (ea_t)GetAddress(SegValue(ds),0); // 0x1970;
   miv->end_ea--;
   strcpy(miv->name, "ROM");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ;
   miv++;

   miv->start_ea = (ea_t)GetAddress(SegValue(ds),0); // 0x1970;
   miv->end_ea = (ea_t)GetAddress(SegValue(cs),0); // 0x1a70; //(ea_t)GetAddress(SegValue(ds),0);
   miv->end_ea--;
   strcpy(miv->name, "PSP");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ;
   miv++;

   miv->start_ea = (ea_t)GetAddress(SegValue(cs),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   miv->end_ea = (ea_t)GetAddress(SegValue(ss), 0); // 0x1c20; //GetAddress(0xf000,0) - 1;
   miv->end_ea--;
   strcpy(miv->name, ".text");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   miv++;

   miv->start_ea = (ea_t)GetAddress(SegValue(ss),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   miv->end_ea = (ea_t)GetAddress(SegValue(ss), 0xffff); //reg_sp); // 0x1c20; //GetAddress(0xf000,0) - 1;
   miv->end_ea--;
   strcpy(miv->name, ".stack");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   miv++;

   miv->start_ea = (ea_t)GetAddress(0xf100,0);
   miv->end_ea = (ea_t)GetAddress(0xf100, 0x1000);
   miv->end_ea--;
   strcpy(miv->name, ".callbacks");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   miv++;
*/

   static bool first_run = true;

   if(!first_run)
        return -2;

   // Read from PSP
   int last_user_seg = mem_readw(GetAddress(app_base>>4, 0x2));
   printf("last user seg = %x\n", last_user_seg);

   memory_info_t *mi = &miv.push_back();
   mi->start_ea = 0x0;
   mi->end_ea = 0x400;
   mi->end_ea--;
   mi->name = "INT_TABLE";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   mi->sbase = 0;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);

   mi = &miv.push_back();
   mi->start_ea = 0x400;
   mi->end_ea = 0x600;
   mi->end_ea--;
   mi->name = "BIOS";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = 0x40;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);
   mi = &miv.push_back();
   mi->start_ea = 0x600;
   mi->end_ea = app_base;
   mi->end_ea--;
   mi->name = "DOS?";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = 0x60;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);

   mi = &miv.push_back();
   mi->start_ea = app_base;
   mi->end_ea = app_base + 0x100;
   mi->end_ea--;
   mi->name = "PSP";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = app_base>>4;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);

   mi = &miv.push_back();
   mi->start_ea = app_base + 0x200;
   mi->end_ea = (ea_t)GetAddress(last_user_seg, 0x10);
   mi->end_ea--;
   mi->name = ".text"; // Not the best name; it also covers data/stack/...
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   mi->sbase = app_base>>4;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);

/*
   // IDA seems to take care of this itself
   mi = &miv.push_back();
   mi->start_ea = (ea_t)GetAddress(SegValue(ss),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   mi->end_ea = (ea_t)GetAddress(SegValue(ss), 0xffff); //reg_sp); // 0x1c20; //GetAddress(0xf000,0) - 1;
   mi->end_ea--;
   mi->name = ".stack";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   mi->sbase = SegValue(ss);
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);
*/
   mi = &miv.push_back();
   mi->start_ea = 0xA0000;
   mi->end_ea = 0xB0000;
   mi->end_ea--;
   mi->name = "A000";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ;
   mi->sbase = 0xa000;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);

   mi = &miv.push_back();
   mi->start_ea = 0xB0000;
   mi->end_ea = 0xB8000;
   mi->end_ea--;
   mi->name = "B000";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   mi->sbase = 0xb000;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);
   mi = &miv.push_back();
   mi->start_ea = 0xB8000;
   mi->end_ea = 0xC0000;
   mi->end_ea--;
   mi->name = "B800";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ |SEGPERM_WRITE;
   mi->sbase = 0xb800;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);
   mi = &miv.push_back();
   mi->start_ea = 0xC0000;
   mi->end_ea = 0xC1000;
   mi->end_ea--;
   mi->name = "VIDBIOS";
   mi->bitness = 0;
   mi->perm = 0 | SEGPERM_READ | SEGPERM_EXEC;
   mi->sbase = 0xc000;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);

   mi = &miv.push_back();
   mi->start_ea = (ea_t)GetAddress(0xf100,0);
   mi->end_ea = (ea_t)GetAddress(0xf100, 0x1000);
   mi->end_ea--;
   mi->name = ".callbacks";
   mi->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   mi->sbase = 0xf100;
printf("mi = %x,%x\n",mi->start_ea, mi->end_ea);

printf("CS:IP = %04x:%04x\n",SegValue(cs), reg_eip);

  first_run = false;

  return 1;
}

int idaapi dosbox_debmod_t::dbg_get_scattered_image(scattered_image_t &si, ea_t base)
{
    printf("GET HERE dbg_get_scattered_image\n");
    return -1; // not implemented
}

bool idaapi dosbox_debmod_t::dbg_get_image_uuid(bytevec_t *uuid, ea_t base)
{
    printf("GET HERE dbg_get_image_uuid\n");
    return false; // not implemented
}

ea_t idaapi dosbox_debmod_t::dbg_get_segm_start(ea_t base, const qstring &segname)
{
    printf("GET HERE dbg_get_segm_start\n");
    return false; // not implemented
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
 int i;
 PhysPt addr = (PhysPt)ea;
 uchar *buf;

 buf = (uchar *)buffer;
 //addr = addr + r_debug.base;

 for(i=0;i<size;i++)
  {
   buf[i] = mem_readb(addr);
   // printf("%02x,",buf[i]);
   addr++;
  }

 printf("dbg_read_memory @ %x, size=%d\n", ea, size);
 return size;
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  if ( ea == 0 )
    return 0;

  for(int i=0;i<size;i++)
    mem_writeb(ea + i, ((Bit8u *)buffer)[i]);

  printf("dbg_write_memory @ %x, size=%d\n", ea, size);
  return size;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_open_file(const char *file, uint64 *fsize, bool readonly)
{
  return 0;
}

//--------------------------------------------------------------------------
void idaapi dosbox_debmod_t::dbg_close_file(int fn)
{
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_read_file(int fn, qoff64_t off, void *buf, size_t size)
{
  return -1;
}

//--------------------------------------------------------------------------
ssize_t idaapi dosbox_debmod_t::dbg_write_file(int fn, qoff64_t off, const void *buf, size_t size)
{
  return -1;
}

//--------------------------------------------------------------------------
int dosbox_debmod_t::get_system_specific_errno(void) const
{
  return errno;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value)
{
  *ea = sreg_value<<4;

  return 1;
}

//--------------------------------------------------------------------------
int idaapi dosbox_debmod_t::dbg_is_ok_bpt(bpttype_t /*type*/, ea_t /*ea*/, int /*len*/)
{
  //return BPT_BAD_ADDR; // not supported
  printf("GET HERE is_ok_bpt\n");
  return BPT_OK;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session()
{
  return new dosbox_debmod_t();
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  return true;
}

//--------------------------------------------------------------------------
bool init_subsystem()
{
  return true;
}

bool dosbox_debmod_t::hit_breakpoint(PhysPt addr)
{
  printf("hit breakpoint! 0x%x\n", addr);
  debug_event_t ev;

  ev.eid = BREAKPOINT;
  ev.pid = NO_PROCESS;
  ev.tid = NO_PROCESS;
  ev.bpt.hea = BADADDR; //addr; //BADADDR; //r_debug.base - addr; //BADADDR; //addr;//r_debug.base - addr;
  ev.bpt.kea = BADADDR;//(ea_t)reg_eip;
  ev.ea = addr;
  ev.handled = false;

/*
  ev.eid = NO_EVENT;
  ev.pid = NO_PROCESS;
  ev.tid = NO_PROCESS;
  ev.ea = addr;
  ev.handled = true;
  ev.exc.code = 0;
  ev.exc.can_cont = true;
  ev.exc.ea = BADADDR;
*/

  events.enqueue(ev, IN_BACK);

  return 1;
}

inline ea_t find_app_base()
{
  ea_t base = (ea_t)GetAddress(SegValue(cs), 0);
  ea_t addr;

  addr = (ea_t)GetAddress(SegValue(ds), 0);

  if(addr < base)
   base = addr;

  addr = (ea_t)GetAddress(SegValue(ss), 0);

  if(addr < base)
   base = addr;

  return base;
}
