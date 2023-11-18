typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef longlong __quad_t;

typedef __quad_t __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char * _IO_read_ptr;
    char * _IO_read_end;
    char * _IO_read_base;
    char * _IO_write_base;
    char * _IO_write_ptr;
    char * _IO_write_end;
    char * _IO_buf_base;
    char * _IO_buf_end;
    char * _IO_save_base;
    char * _IO_backup_base;
    char * _IO_save_end;
    struct _IO_marker * _markers;
    struct _IO_FILE * _chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t * _lock;
    __off64_t _offset;
    void * __pad1;
    void * __pad2;
    void * __pad3;
    void * __pad4;
    size_t __pad5;
    int _mode;
    char _unused2[40];
};

struct _IO_marker {
    struct _IO_marker * _next;
    struct _IO_FILE * _sbuf;
    int _pos;
};

typedef struct stat stat, *Pstat;

typedef ulonglong __u_quad_t;

typedef __u_quad_t __dev_t;

typedef ulong __ino_t;

typedef uint __mode_t;

typedef uint __nlink_t;

typedef uint __uid_t;

typedef uint __gid_t;

typedef long __blksize_t;

typedef long __blkcnt_t;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

struct stat {
    __dev_t st_dev;
    ushort __pad1;
    __ino_t st_ino;
    __mode_t st_mode;
    __nlink_t st_nlink;
    __uid_t st_uid;
    __gid_t st_gid;
    __dev_t st_rdev;
    ushort __pad2;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    ulong __unused4;
    ulong __unused5;
};

typedef int __clockid_t;

typedef __clockid_t clockid_t;

typedef struct _IO_FILE FILE;

typedef struct pollfd pollfd, *Ppollfd;

struct pollfd {
    int fd;
    short events;
    short revents;
};

typedef ulong nfds_t;

typedef ulonglong uint64_t;

typedef uint64_t eventfd_t;

typedef struct __pthread_internal_slist __pthread_internal_slist, *P__pthread_internal_slist;

struct __pthread_internal_slist {
    struct __pthread_internal_slist * __next;
};

typedef union pthread_mutex_t pthread_mutex_t, *Ppthread_mutex_t;

typedef struct __pthread_mutex_s __pthread_mutex_s, *P__pthread_mutex_s;

typedef union _union_13 _union_13, *P_union_13;

typedef struct __pthread_internal_slist __pthread_slist_t;

union _union_13 {
    int __spins;
    __pthread_slist_t __list;
};

struct __pthread_mutex_s {
    int __lock;
    uint __count;
    int __owner;
    int __kind;
    uint __nusers;
    union _union_13 field5_0x14;
};

union pthread_mutex_t {
    struct __pthread_mutex_s __data;
    char __size[24];
    long __align;
};

typedef union pthread_condattr_t pthread_condattr_t, *Ppthread_condattr_t;

union pthread_condattr_t {
    char __size[4];
    int __align;
};

typedef union pthread_mutexattr_t pthread_mutexattr_t, *Ppthread_mutexattr_t;

union pthread_mutexattr_t {
    char __size[4];
    int __align;
};

typedef union pthread_cond_t pthread_cond_t, *Ppthread_cond_t;

typedef struct _struct_16 _struct_16, *P_struct_16;

struct _struct_16 {
    int __lock;
    uint __futex;
    ulonglong __total_seq;
    ulonglong __wakeup_seq;
    ulonglong __woken_seq;
    void * __mutex;
    uint __nwaiters;
    uint __broadcast_seq;
};

union pthread_cond_t {
    struct _struct_16 __data;
    char __size[48];
    longlong __align;
};

typedef ulong pthread_t;

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[36];
    long __align;
};

typedef enum Elf32_DynTag_x86 {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf32_DynTag_x86;

typedef struct Elf32_Dyn_x86 Elf32_Dyn_x86, *PElf32_Dyn_x86;

struct Elf32_Dyn_x86 {
    enum Elf32_DynTag_x86 d_tag;
    dword d_val;
};

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_x86 {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482
} Elf_ProgramHeaderType_x86;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType_x86 p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef struct Gnu_BuildId Gnu_BuildId, *PGnu_BuildId;

struct Gnu_BuildId {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Build-id vendor name
    byte description[20]; // Build-id value
};

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
};

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

typedef enum Elf_SectionHeaderType_x86 {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191
} Elf_SectionHeaderType_x86;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_x86 sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};




void FUN_00011ad0(void)

{
                    // WARNING: Treating indirect jump as call
  (*(code *)(undefined *)0x0)();
  return;
}



void __i686_get_pc_thunk_bx(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00011ec0(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  undefined **ppuVar5;
  undefined *puVar6;
  undefined4 uVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined4 uStack48;
  undefined4 uStack44;
  undefined4 uStack40;
  int iStack24;
  
  puVar9 = &stack0xfffffffc;
  ppuVar5 = &__DT_PLTGOT;
  puVar8 = &__stack_chk_guard;
  iStack24 = ___stack_chk_guard;
  iVar2 = func_0x00011b10(param_1,param_2,&uStack48);
  if (iVar2 != 0) {
    FUN_00013760(param_1,1,&UNK_00017a60);
    iVar3 = -2;
    uVar7 = param_1;
    goto LAB_00011f7f;
  }
  *(undefined4 *)(param_3 + 0x54) = uStack48;
  uVar7 = param_1;
  iVar2 = func_0x00011b20(param_1,param_2,param_4);
  if (iVar2 + 3U < 4) {
    puVar6 = &UNK_00017a7a;
    iVar3 = 0;
    iVar1 = -1;
    switch(iVar2) {
    case 0:
      goto LAB_00011f7f;
    case -2:
      puVar6 = &UNK_00017a9b;
    case -1:
code_r0x00011f67:
      FUN_00013760(param_1,1,puVar6);
      iVar1 = -2;
      uVar7 = param_1;
    case -3:
      iVar3 = iVar1;
LAB_00011f7f:
      if (___stack_chk_guard == iStack24) {
        return iVar3;
      }
      func_0x00011af0();
      puVar6 = &LAB_00011fad;
      iVar2 = func_0x00011b30(uStack44,uStack40);
      if (iVar2 != 0) {
        if (iVar2 == -1) {
          puVar4 = &UNK_00017ace;
        }
        else if (iVar2 == -2) {
          puVar4 = &UNK_00017af1;
        }
        else {
          puVar4 = &UNK_00017b14;
        }
        iVar2 = FUN_00013760(uStack44,1,puVar4,puVar6,uVar7,puVar8,ppuVar5,puVar9);
      }
      return iVar2;
    }
  }
  puVar6 = &UNK_00017abc;
  goto code_r0x00011f67;
}



void FUN_00011fa0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined *puVar2;
  
  iVar1 = func_0x00011b30(param_1,param_2);
  if (iVar1 != 0) {
    if (iVar1 == -1) {
      puVar2 = &UNK_00017ace;
    }
    else if (iVar1 == -2) {
      puVar2 = &UNK_00017af1;
    }
    else {
      puVar2 = &UNK_00017b14;
    }
    FUN_00013760(param_1,1,puVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint Java_pl_droidsonroids_gif_GifInfoHandle_renderFrame
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
               undefined4 param_5)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  int iStack60;
  undefined4 uStack52;
  undefined4 auStack48 [6];
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  if (param_3 == 0) {
    uVar3 = 0xffffffff;
    goto LAB_0001213a;
  }
  uVar1 = FUN_000179d0();
  iVar2 = func_0x00011b10(param_1,param_5,auStack48);
  if (iVar2 != 0) {
    puVar4 = &UNK_00017a60;
    goto LAB_0001212a;
  }
  *(undefined4 *)(param_3 + 0x54) = auStack48[0];
  iVar2 = func_0x00011b20(param_1,param_5,&uStack52);
  if (3 < iVar2 + 3U) {
    puVar4 = &UNK_00017abc;
    goto LAB_0001212a;
  }
  puVar4 = &UNK_00017a7a;
  switch(iVar2) {
  case 0:
    FUN_000126e0(param_3,1,0);
    if (*(int *)(param_3 + 0x24) == 0) {
      FUN_00013000(uStack52,param_3);
    }
    iStack60 = FUN_000136d0(uStack52,param_3);
    iVar2 = func_0x00011b30(param_1,param_5);
    if (iVar2 != 0) {
      if (iVar2 == -1) {
        puVar4 = &UNK_00017ace;
      }
      else if (iVar2 == -2) {
        puVar4 = &UNK_00017af1;
      }
      else {
        puVar4 = &UNK_00017b14;
      }
      FUN_00013760(param_1,1,puVar4);
    }
    uVar3 = FUN_000178b0(param_3,uVar1,iStack60);
    goto LAB_0001213a;
  case -2:
    puVar4 = &UNK_00017a9b;
  case -1:
LAB_0001212a:
    FUN_00013760(param_1,1,puVar4);
  case -3:
    uVar3 = 0;
LAB_0001213a:
    if (___stack_chk_guard != iStack24) {
      func_0x00011af0();
      iVar2 = (**(code **)(iStack60 + 0x4c))(iStack60);
      if (iVar2 == 0) {
        *(undefined4 *)(iStack60 + 0x48) = 0;
        *(undefined4 *)(iStack60 + 0x24) = 0;
        *(undefined4 *)(iStack60 + 0x14) = 0xffffffff;
        *(undefined4 *)(iStack60 + 0x18) = 0xffffffff;
        *(undefined4 *)(iStack60 + 0x1c) = 0;
        *(undefined4 *)(iStack60 + 0x20) = 0;
      }
      return (uint)(iVar2 == 0);
    }
    return uVar3;
  }
}



bool FUN_00012190(int param_1)

{
  int iVar1;
  
  iVar1 = (**(code **)(param_1 + 0x4c))(param_1);
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0x48) = 0;
    *(undefined4 *)(param_1 + 0x24) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0xffffffff;
    *(undefined4 *)(param_1 + 0x18) = 0xffffffff;
    *(undefined4 *)(param_1 + 0x1c) = 0;
    *(undefined4 *)(param_1 + 0x20) = 0;
  }
  return iVar1 == 0;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_reset(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  if ((param_3 != 0) && (iVar1 = (**(code **)(param_3 + 0x4c))(param_3), iVar1 == 0)) {
    *(undefined4 *)(param_3 + 0x48) = 0;
    *(undefined4 *)(param_3 + 0x24) = 0;
    *(undefined4 *)(param_3 + 0x14) = 0xffffffff;
    *(undefined4 *)(param_3 + 0x18) = 0xffffffff;
    *(undefined4 *)(param_3 + 0x1c) = 0;
    *(undefined4 *)(param_3 + 0x20) = 0;
    return 1;
  }
  return 0;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_setSpeedFactor
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
               undefined4 param_5)

{
  if (param_3 != 0) {
    *(undefined4 *)(param_3 + 0x50) = param_5;
  }
  return;
}



undefined4 FUN_00012250(int param_1,uint param_2,undefined4 param_3)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  
  uVar4 = *(uint *)(param_1 + 0x24);
  piVar1 = *(int **)(param_1 + 4);
  if (param_2 <= uVar4 - 1) {
    iVar2 = (**(code **)(param_1 + 0x4c))(param_1);
    if (iVar2 != 0) {
      piVar1[0xc] = 0x3ec;
      return 0;
    }
    *(undefined4 *)(param_1 + 0x48) = 0;
    *(undefined4 *)(param_1 + 0x24) = 0;
    *(undefined4 *)(param_1 + 0x14) = 0xffffffff;
    *(undefined4 *)(param_1 + 0x18) = 0xffffffff;
    *(undefined4 *)(param_1 + 0x1c) = 0;
    *(undefined4 *)(param_1 + 0x20) = 0;
    FUN_00013000(param_3,param_1);
    uVar4 = *(uint *)(param_1 + 0x24);
  }
  uVar6 = piVar1[4] - 1;
  if (param_2 < (uint)piVar1[4]) {
    uVar6 = param_2;
  }
  uVar7 = uVar6;
  if (uVar4 < uVar6) {
    iVar2 = *(int *)(*(int *)(param_1 + 4) + 0x2c);
    iVar3 = uVar6 * 0xc;
    do {
      if (((*piVar1 == *(int *)(iVar2 + 8 + iVar3 * 2)) &&
          (piVar1[1] == *(int *)(iVar2 + 0xc + iVar3 * 2))) &&
         ((*(int *)(*(int *)(param_1 + 0x28) + 8 + iVar3) == -1 ||
          (*(char *)(*(int *)(param_1 + 0x28) + iVar3) == '\x02')))) goto LAB_00012345;
      uVar7 = uVar7 - 1;
      iVar3 = iVar3 + -0xc;
    } while (uVar4 < uVar7);
  }
  if (uVar7 != 0) {
LAB_00012345:
    while (uVar4 < uVar7 - 1) {
      FUN_000126e0(param_1,0,1);
      uVar4 = *(int *)(param_1 + 0x24) + 1;
      *(uint *)(param_1 + 0x24) = uVar4;
    }
  }
  do {
    FUN_000126e0(param_1,1,0);
    FUN_000130e0(param_3,param_1);
    uVar4 = *(uint *)(param_1 + 0x24);
    *(uint *)(param_1 + 0x24) = uVar4 + 1;
  } while (uVar4 < uVar6);
  *(uint *)(param_1 + 0x24) = uVar4;
  uVar5 = FUN_00013650(param_1);
  return uVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_pl_droidsonroids_gif_GifInfoHandle_seekToTime
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,uint param_5,
               undefined4 param_6)

{
  undefined **ppuVar1;
  undefined **ppuVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  uint uVar7;
  int iVar8;
  int unaff_ESI;
  int *piVar9;
  uint unaff_EDI;
  int iVar10;
  float fVar11;
  undefined4 uStack76;
  int iStack72;
  int iStack68;
  int iStack64;
  uint uStack60;
  undefined **ppuStack56;
  int *piStack52;
  undefined4 uStack44;
  int *piStack40;
  undefined **ppuStack36;
  float fStack32;
  int iStack28;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  piVar9 = (int *)&__stack_chk_guard;
  if ((param_3 != 0) && (iVar4 = *(int *)(*(int *)(param_3 + 4) + 0x10), iVar4 != 1)) {
    uVar3 = iVar4 - 1;
    piVar9 = (int *)(*(int *)(param_3 + 0x28) + 4);
    unaff_EDI = 0;
    uVar5 = 0;
    do {
      uVar7 = *piVar9 + uVar5;
      if (param_5 < uVar7) break;
      unaff_EDI = unaff_EDI + 1;
      piVar9 = piVar9 + 3;
      uVar5 = uVar7;
    } while (unaff_EDI < uVar3);
    if ((*(uint *)(param_3 + 0x14) & *(uint *)(param_3 + 0x18)) != 0xffffffff) {
      *(uint *)(param_3 + 0x14) = param_5 - uVar5;
      *(undefined4 *)(param_3 + 0x18) = 0;
      if ((unaff_EDI == uVar3) &&
         (uVar3 = *(uint *)(*(int *)(param_3 + 0x28) + 4 + uVar3 * 0xc), uVar3 < param_5 - uVar5)) {
        *(uint *)(param_3 + 0x14) = uVar3;
        *(undefined4 *)(param_3 + 0x18) = 0;
      }
    }
    piStack52 = &iStack28;
    ppuStack56 = (undefined **)param_3;
    uStack60 = param_6;
    iStack64 = param_1;
    iStack68 = 0x12473;
    piStack40 = (int *)&__stack_chk_guard;
    ppuStack36 = &__DT_PLTGOT;
    iVar4 = FUN_00011ec0();
    if (iVar4 == 0) {
      ppuStack56 = (undefined **)iStack28;
      iStack64 = param_3;
      iStack68 = 0x12488;
      uStack60 = unaff_EDI;
      FUN_00012250();
      uStack60 = param_6;
      iStack64 = param_1;
      iStack68 = 0x12496;
      FUN_00011fa0();
    }
    piStack52 = (int *)0x1249e;
    iVar4 = FUN_000179d0();
    fStack32 = (float)*(longlong *)(param_3 + 0x14);
    iVar4 = (int)(fStack32 / *(float *)(param_3 + 0x50)) + iVar4;
    *(int *)(param_3 + 0x1c) = iVar4;
    *(int *)(param_3 + 0x20) = iVar4 >> 0x1f;
    piVar9 = piStack40;
    unaff_ESI = param_3;
  }
  if (*piVar9 == iStack24) {
    return;
  }
  piStack52 = (int *)0x124d8;
  func_0x00011af0();
  ppuVar1 = ppuStack36;
  ppuStack56 = &__DT_PLTGOT;
  iStack72 = ___stack_chk_guard;
  iStack64 = unaff_ESI;
  uStack60 = unaff_EDI;
  ppuVar2 = &__DT_PLTGOT;
  piStack52 = (int *)&stack0xfffffffc;
  if ((ppuStack36 != (undefined **)0x0) &&
     (ppuVar2 = ppuStack56, piStack52 = (int *)&stack0xfffffffc, *(int *)(ppuStack36[1] + 0x10) != 1
     )) {
    ppuStack56 = &__DT_PLTGOT;
    piStack52 = (int *)&stack0xfffffffc;
    iVar4 = FUN_00011ec0(uStack44,iStack24,ppuStack36,&uStack76);
    fVar11 = 0.0;
    if (iVar4 == 0) {
      uVar5 = FUN_00012250(ppuVar1,iStack28,uStack76);
      FUN_00011fa0(uStack44,iStack24);
      fVar11 = (float)((double)((ulonglong)uVar5 | 0x4330000000000000) - 4503599627370496.0);
    }
    iVar4 = FUN_000179d0();
    puVar6 = (undefined *)((int)(fVar11 / (float)ppuVar1[0x14]) + iVar4);
    ppuVar1[7] = puVar6;
    ppuVar1[8] = (undefined *)((int)puVar6 >> 0x1f);
    ppuVar2 = ppuStack56;
    if (((uint)ppuVar1[5] & (uint)ppuVar1[6]) != 0xffffffff) {
      ppuVar1[6] = (undefined *)0x0;
      ppuVar1[5] = (undefined *)0x0;
    }
  }
  ppuStack56 = ppuVar2;
  if (___stack_chk_guard == iStack72) {
    return;
  }
  func_0x00011af0();
  iVar4 = iStack68;
  if ((((iStack68 != 0) && ((*(uint *)(iStack68 + 0x14) & *(uint *)(iStack68 + 0x18)) == 0xffffffff)
       ) && (iVar10 = *(int *)(*(int *)(iStack68 + 4) + 0x10), *(int *)(iStack68 + 0x24) != iVar10))
     && (iVar10 != 1)) {
    uVar5 = *(uint *)(iStack68 + 0x1c);
    iVar10 = *(int *)(iStack68 + 0x20);
    uVar3 = FUN_000179d0();
    iVar8 = uVar5 - uVar3;
    iVar10 = (iVar10 - ((int)uVar3 >> 0x1f)) - (uint)(uVar5 < uVar3);
    if (iVar10 < 0) {
      iVar8 = 0;
      iVar10 = 0;
    }
    *(int *)(iVar4 + 0x18) = iVar10;
    *(int *)(iVar4 + 0x14) = iVar8;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_pl_droidsonroids_gif_GifInfoHandle_seekToFrame
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
               undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  float fVar5;
  undefined4 uStack28;
  int iStack24;
  int iStack20;
  
  iStack24 = ___stack_chk_guard;
  if ((param_3 != 0) && (*(int *)(*(int *)(param_3 + 4) + 0x10) != 1)) {
    iVar1 = FUN_00011ec0(param_1,param_6,param_3,&uStack28);
    fVar5 = 0.0;
    if (iVar1 == 0) {
      uVar2 = FUN_00012250(param_3,param_5,uStack28);
      FUN_00011fa0(param_1,param_6);
      fVar5 = (float)((double)((ulonglong)uVar2 | 0x4330000000000000) - 4503599627370496.0);
    }
    iVar1 = FUN_000179d0();
    iVar1 = (int)(fVar5 / *(float *)(param_3 + 0x50)) + iVar1;
    *(int *)(param_3 + 0x1c) = iVar1;
    *(int *)(param_3 + 0x20) = iVar1 >> 0x1f;
    if ((*(uint *)(param_3 + 0x14) & *(uint *)(param_3 + 0x18)) != 0xffffffff) {
      *(undefined4 *)(param_3 + 0x18) = 0;
      *(undefined4 *)(param_3 + 0x14) = 0;
    }
  }
  if (___stack_chk_guard != iStack24) {
    func_0x00011af0();
    if ((((iStack20 != 0) &&
         ((*(uint *)(iStack20 + 0x14) & *(uint *)(iStack20 + 0x18)) == 0xffffffff)) &&
        (iVar1 = *(int *)(*(int *)(iStack20 + 4) + 0x10), *(int *)(iStack20 + 0x24) != iVar1)) &&
       (iVar1 != 1)) {
      uVar2 = *(uint *)(iStack20 + 0x1c);
      iVar1 = *(int *)(iStack20 + 0x20);
      uVar3 = FUN_000179d0();
      iVar4 = uVar2 - uVar3;
      iVar1 = (iVar1 - ((int)uVar3 >> 0x1f)) - (uint)(uVar2 < uVar3);
      if (iVar1 < 0) {
        iVar4 = 0;
        iVar1 = 0;
      }
      *(int *)(iStack20 + 0x18) = iVar1;
      *(int *)(iStack20 + 0x14) = iVar4;
    }
    return;
  }
  return;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_saveRemainder
               (undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  if ((((param_3 != 0) && ((*(uint *)(param_3 + 0x14) & *(uint *)(param_3 + 0x18)) == 0xffffffff))
      && (iVar4 = *(int *)(*(int *)(param_3 + 4) + 0x10), *(int *)(param_3 + 0x24) != iVar4)) &&
     (iVar4 != 1)) {
    uVar1 = *(uint *)(param_3 + 0x1c);
    iVar4 = *(int *)(param_3 + 0x20);
    uVar2 = FUN_000179d0();
    iVar3 = uVar1 - uVar2;
    iVar4 = (iVar4 - ((int)uVar2 >> 0x1f)) - (uint)(uVar1 < uVar2);
    if (iVar4 < 0) {
      iVar3 = 0;
      iVar4 = 0;
    }
    *(int *)(param_3 + 0x18) = iVar4;
    *(int *)(param_3 + 0x14) = iVar3;
  }
  return;
}



undefined8
Java_pl_droidsonroids_gif_GifInfoHandle_restoreRemainder
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  if ((param_3 == 0) || ((*(uint *)(param_3 + 0x14) & *(uint *)(param_3 + 0x18)) == 0xffffffff)) {
    uVar1 = 0xffffffff;
    iVar3 = -1;
  }
  else {
    uVar1 = 0xffffffff;
    iVar3 = -1;
    if (*(int *)(*(int *)(param_3 + 4) + 0x10) != 1) {
      if (*(int *)(param_3 + 0x44) != 0) {
        uVar1 = 0xffffffff;
        iVar3 = -1;
        if (*(int *)(param_3 + 0x48) == *(int *)(param_3 + 0x44)) goto LAB_000126c9;
      }
      uVar2 = FUN_000179d0();
      uVar1 = *(uint *)(param_3 + 0x14);
      iVar3 = *(int *)(param_3 + 0x18);
      *(uint *)(param_3 + 0x1c) = uVar2 + uVar1;
      *(uint *)(param_3 + 0x20) = ((int)uVar2 >> 0x1f) + iVar3 + (uint)CARRY4(uVar2,uVar1);
      *(undefined4 *)(param_3 + 0x18) = 0xffffffff;
      *(undefined4 *)(param_3 + 0x14) = 0xffffffff;
    }
  }
LAB_000126c9:
  return CONCAT44(iVar3,uVar1);
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_000126e0(uint *param_1,byte param_2,byte param_3)

{
  byte bVar1;
  uint uVar2;
  code *pcVar3;
  char cVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int extraout_ECX;
  undefined4 uVar10;
  uint *puVar11;
  byte *extraout_EDX;
  undefined **ppuVar12;
  uint *puVar13;
  int *piVar14;
  uint *puVar15;
  undefined4 *puVar16;
  int *piStack124;
  code **ppcStack116;
  byte *pbStack108;
  int iStack104;
  undefined4 uStack100;
  uint *puStack96;
  uint *puStack92;
  undefined **ppuStack88;
  undefined *puStack84;
  int iStack76;
  uint *puStack72;
  uint *puStack68;
  uint *puStack64;
  uint uStack60;
  uint *puStack56;
  uint uStack52;
  undefined **ppuStack48;
  int *piStack44;
  uint uStack40;
  int iStack36;
  int iStack32;
  int iStack28;
  int iStack24;
  
  puStack84 = &LAB_000126f1;
  ppuVar12 = &__DT_PLTGOT;
  piStack44 = (int *)&__stack_chk_guard;
  iStack24 = ___stack_chk_guard;
  puStack64 = (uint *)((uint)puStack64 & 0xffffff00 | (uint)(param_2 | param_3));
  uStack52 = (uStack52 & 0xffffff00 | (uint)(param_2 | param_3)) ^ 1;
  puStack72 = (uint *)param_1[1];
  puStack68 = (uint *)0x0;
  puVar15 = puStack72;
  ppuStack48 = ppuVar12;
  do {
    puStack92 = (uint *)&iStack28;
    uStack100 = 0x1274e;
    puStack96 = puVar15;
    iVar5 = FUN_00014c80();
    puVar11 = param_1;
    if (iVar5 == 0) break;
    if (iStack28 == 3) {
      ppuStack88 = (undefined **)&iStack32;
      puStack92 = (uint *)&iStack36;
      uStack100 = 0x128e3;
      puStack96 = puVar15;
      iVar5 = FUN_00015920();
      puVar13 = puStack72;
      if (iVar5 != 0) {
        puVar15 = puStack72;
        if ((char)puStack64 == '\0') {
          if (puStack68 < *(uint **)(param_1[1] + 0x10)) {
            puStack92 = (uint *)((int)*(uint **)(param_1[1] + 0x10) + 1);
            ppuStack88 = (undefined **)0xc;
            puStack96 = (uint *)param_1[10];
            uStack100 = 0x12918;
            uVar6 = FUN_00015cf0();
            if (uVar6 == 0) {
              *(undefined4 *)(param_1[1] + 0x30) = 0x6d;
            }
            else {
              puStack68 = *(uint **)(param_1[1] + 0x10);
              param_1[10] = uVar6;
              puStack96 = (uint *)(uVar6 + (int)puStack68 * 0xc);
              uStack100 = 0x1293b;
              FUN_00015fb0();
            }
          }
          uStack100 = 0x129a0;
          puStack96 = param_1;
          iVar5 = FUN_00012c00();
          puVar13 = puStack72;
          puVar15 = puStack72;
          if (iVar5 == 0) goto LAB_00012a28;
        }
        while (puStack72 = puVar15, puVar15 = puStack72, puStack72 = puVar13, iStack32 != 0) {
          while( true ) {
            puStack92 = (uint *)&iStack32;
            puStack96 = puVar15;
            uStack100 = 0x129ce;
            iVar5 = FUN_00015a00();
            puVar13 = puStack72;
            if (iVar5 == 0) goto LAB_00012a28;
            if ((char)puStack64 != '\0') break;
            uStack100 = 0x12a01;
            puStack96 = param_1;
            iVar5 = FUN_00012c00();
            puVar13 = puStack72;
            if ((iVar5 == 0) || (iStack32 == 0)) goto LAB_00012a28;
          }
        }
      }
    }
    else {
      puVar13 = puVar15;
      if (iStack28 == 2) {
        puStack92 = (uint *)(uStack52 & 0xff);
        uStack100 = 0x12783;
        puStack96 = puVar15;
        iVar5 = FUN_00014d20();
        puVar13 = puStack72;
        if (iVar5 != 0) {
          if ((char)puStack64 == '\0') {
            uVar6 = puVar15[7];
            uStack60 = *puVar15;
            uVar7 = puVar15[8];
            if ((uVar6 != uStack60 && -1 < (int)(uVar6 - uStack60)) ||
               (uStack40 = puVar15[1], ppuVar12 = ppuStack48,
               uVar7 != uStack40 && -1 < (int)(uVar7 - uStack40))) {
              *puVar15 = uVar6;
              puVar15[1] = uVar7;
              uStack40 = uVar7;
              uStack60 = uVar6;
            }
            uVar2 = puVar15[4];
            puStack56 = (uint *)puVar15[0xb];
            iVar5 = (uVar7 + puVar15[6]) - uStack40;
            if (0 < iVar5) {
              puStack56[(uVar2 - 1) * 6 + 1] = puStack56[(uVar2 - 1) * 6 + 1] - iVar5;
            }
            iVar5 = (uVar6 + puStack72[5]) - uStack60;
            if (0 < iVar5) {
              puStack56[(uVar2 - 1) * 6] = puStack56[(uVar2 - 1) * 6] - iVar5;
            }
            puVar15 = puStack72;
            if (puStack68 < *(uint **)(param_1[1] + 0x10)) {
              puStack92 = (uint *)((int)*(uint **)(param_1[1] + 0x10) + 1);
              ppuStack88 = (undefined **)0xc;
              puStack96 = (uint *)param_1[10];
              uStack100 = 0x12823;
              uVar6 = FUN_00015cf0();
              puVar15 = puStack72;
              if (uVar6 == 0) {
                *(undefined4 *)(param_1[1] + 0x30) = 0x6d;
                puVar13 = puStack72;
                goto LAB_00012a28;
              }
              puStack68 = *(uint **)(param_1[1] + 0x10);
              param_1[10] = uVar6;
              puStack96 = (uint *)(uVar6 + (int)puStack68 * 0xc);
              uStack100 = 0x1284e;
              FUN_00015fb0();
            }
          }
          if (param_2 == 0) {
            do {
              puStack92 = (uint *)&iStack32;
              uStack100 = 0x1295e;
              puStack96 = puVar15;
              iVar5 = FUN_00015860();
              if (iVar5 == 0) break;
            } while (iStack32 != 0);
            puVar13 = puStack72;
            if (param_3 != 0) goto LAB_00012a3b;
          }
          else {
            uVar6 = puVar15[7];
            uVar7 = puVar15[8];
            piVar14 = (int *)(uVar7 * uVar6);
            if (((uVar7 != param_1[3] && -1 < (int)(uVar7 - param_1[3])) ||
                (uVar6 != param_1[2] && -1 < (int)(uVar6 - param_1[2]))) ||
               ((int *)param_1[0xf] <= piVar14 && (int)piVar14 - (int)param_1[0xf] != 0)) {
              ppuStack88 = (undefined **)0x1;
              puStack96 = (uint *)param_1[0xe];
              uStack100 = 0x12887;
              puStack92 = (uint *)piVar14;
              uVar6 = FUN_00015cf0();
              if (uVar6 == 0) {
                puStack72[0xc] = 0x6d;
                puVar13 = puStack72;
                goto LAB_00012a28;
              }
              param_1[0xe] = uVar6;
              param_1[0xf] = (uint)piVar14;
            }
            if (*(char *)(puStack72 + 9) != '\0') {
              if (puStack72[8] == 0) goto LAB_00012b61;
              uVar6 = 0;
              goto LAB_00012a70;
            }
            ppuStack88 = (undefined **)(puStack72[8] * puStack72[7]);
            puStack92 = (uint *)param_1[0xe];
            puStack96 = puStack72;
            uStack100 = 0x128ba;
            iVar5 = FUN_00015070();
            puVar13 = puStack72;
            if (iVar5 != 0) goto LAB_00012b61;
          }
        }
      }
    }
LAB_00012a28:
    puVar15 = puVar13;
  } while (iStack28 != 4);
  uStack100 = 0x12a38;
  puStack96 = param_1;
  (*(code *)param_1[0x13])();
  goto LAB_00012a3b;
  while( true ) {
    uVar6 = uVar6 + 8;
    uVar7 = puStack72[8];
    if (uVar7 <= uVar6) break;
LAB_00012a70:
    ppuStack88 = (undefined **)puStack72[7];
    puStack92 = (uint *)((int)ppuStack88 * uVar6 + param_1[0xe]);
    puStack96 = puStack72;
    uStack100 = 0x12a86;
    iVar5 = FUN_00015070();
    if (iVar5 == 0) {
      uVar7 = puStack72[8];
      break;
    }
  }
  if (4 < uVar7) {
    uVar6 = 4;
    do {
      ppuStack88 = (undefined **)puStack72[7];
      puStack92 = (uint *)((int)ppuStack88 * uVar6 + param_1[0xe]);
      puStack96 = puStack72;
      uStack100 = 0x12ac8;
      iVar5 = FUN_00015070();
      if (iVar5 == 0) {
        uVar7 = puStack72[8];
        break;
      }
      uVar6 = uVar6 + 8;
      uVar7 = puStack72[8];
    } while (uVar6 < uVar7);
  }
  if (2 < uVar7) {
    uVar6 = 2;
    do {
      ppuStack88 = (undefined **)puStack72[7];
      puStack92 = (uint *)((int)ppuStack88 * uVar6 + param_1[0xe]);
      uStack100 = 0x12b0a;
      puStack96 = puStack72;
      iVar5 = FUN_00015070();
      if (iVar5 == 0) {
        uVar7 = puStack72[8];
        break;
      }
      uVar6 = uVar6 + 4;
      uVar7 = puStack72[8];
    } while (uVar6 < uVar7);
  }
  if (1 < uVar7) {
    uVar6 = 1;
    do {
      ppuStack88 = (undefined **)puStack72[7];
      puStack92 = (uint *)((int)ppuStack88 * uVar6 + param_1[0xe]);
      puStack96 = puStack72;
      uStack100 = 0x12b4e;
      iVar5 = FUN_00015070();
      if (iVar5 == 0) break;
      uVar6 = uVar6 + 2;
    } while (uVar6 < puStack72[8]);
  }
LAB_00012b61:
  puVar15 = (uint *)param_1[4];
  if ((uint *)0x1 < puVar15) {
    puStack68 = (uint *)param_1[0xe];
    uVar6 = puStack72[7];
    puStack56 = (uint *)(puStack72[8] * uVar6 + (int)puStack68);
    puStack64 = puStack68;
    while( true ) {
      uStack52 = (int)puVar15 * uVar6;
      uStack60 = uVar6 / (uint)puVar15;
      puVar11 = puStack64;
      puVar13 = puStack68;
      do {
        *(undefined *)puVar13 = *(undefined *)puVar11;
        puVar13 = (uint *)((int)puVar13 + 1);
        puVar15 = (uint *)param_1[4];
        puVar11 = (uint *)((int)puVar11 + (int)puVar15);
      } while (puVar11 < (uint *)((int)puStack64 + uVar6));
      puVar11 = (uint *)((int)puStack64 + uStack52);
      ppuVar12 = ppuStack48;
      if (puStack56 <= puVar11) break;
      puStack68 = (uint *)((int)puStack68 + uStack60);
      uVar6 = puStack72[7];
      puStack64 = puVar11;
    }
  }
LAB_00012a3b:
  if (*piStack44 == iStack24) {
    return *piStack44;
  }
  puStack84 = (undefined *)0x12bfb;
  func_0x00011af0();
  iStack104 = ___stack_chk_guard;
  iVar5 = 1;
  pbStack108 = extraout_EDX;
  puStack96 = puVar11;
  puStack92 = puVar15;
  ppuStack88 = ppuVar12;
  puStack84 = &stack0xfffffffc;
  if (extraout_EDX != (byte *)0x0) {
    if (extraout_ECX == 0xff) {
      bVar1 = *extraout_EDX;
      puStack84 = &stack0xfffffffc;
      iVar5 = func_0x00011b40(&UNK_00017b28,extraout_EDX + 1,bVar1);
      if ((iVar5 == 0) ||
         (iVar5 = func_0x00011b40(&UNK_00017b34,extraout_EDX + 1,bVar1), iVar5 == 0)) {
        iVar5 = FUN_00015a00(*(undefined4 *)(iStack76 + 4),&pbStack108);
        if (iVar5 == 0) goto LAB_00012df3;
        iVar5 = 1;
        if (((pbStack108 != (byte *)0x0) && (*pbStack108 == 3)) && (pbStack108[1] == 1)) {
          iVar5 = (uint)pbStack108[3] * 0x100 + (uint)pbStack108[2];
          iVar9 = (uint)pbStack108[3] * 0x100 + 1 + (uint)pbStack108[2];
          if (iVar5 == 0) {
            iVar9 = iVar5;
          }
          iVar5 = 1;
          *(int *)(iStack76 + 0x44) = iVar9;
        }
      }
      else {
        iVar5 = 1;
      }
    }
    else if (extraout_ECX == 0xfe) {
      ppcStack116 = (code **)(uint)*extraout_EDX;
      iVar5 = *(int *)(iStack76 + 0x40);
      if (iVar5 == 0) {
        iVar9 = 0;
        puStack84 = &stack0xfffffffc;
      }
      else {
        puStack84 = &stack0xfffffffc;
        iVar9 = func_0x00011b50(iVar5);
      }
      iVar5 = FUN_00015cf0(iVar5,iVar9 + 1 + (int)ppcStack116,1);
      if (iVar5 == 0) {
        *(undefined4 *)(*(int *)(iStack76 + 4) + 0x30) = 0x6d;
LAB_00012df3:
        iVar5 = 0;
      }
      else {
        func_0x00011b60(iVar5 + iVar9,extraout_EDX + 1,ppcStack116);
        *(undefined *)((int)ppcStack116 + iVar5 + iVar9) = 0;
        *(int *)(iStack76 + 0x40) = iVar5;
        iVar5 = 1;
      }
    }
    else {
      puStack84 = &stack0xfffffffc;
      if (extraout_ECX == 0xf9) {
        iVar5 = *(int *)(iStack76 + 0x28);
        iVar9 = *(int *)(*(int *)(iStack76 + 4) + 0x10);
        ppcStack116 = (code **)(iVar9 * 3);
        puStack84 = &stack0xfffffffc;
        iVar8 = FUN_00015ab0(*extraout_EDX,extraout_EDX + 1,iVar5 + iVar9 * 0xc);
        if (iVar8 == 0) goto LAB_00012df3;
        uVar6 = *(uint *)(iVar5 + 4 + iVar9 * 0xc);
        iVar8 = 100;
        if (1 < uVar6) {
          iVar8 = uVar6 * 10;
        }
        *(int *)(iVar5 + 4 + iVar9 * 0xc) = iVar8;
        iVar5 = 1;
      }
    }
  }
  if (___stack_chk_guard == iStack104) {
    return iVar5;
  }
  iVar5 = func_0x00011af0();
  if (ppcStack116 == (code **)0x0) {
    return iVar5;
  }
  if (*ppcStack116 != (code *)0x0) {
    (**ppcStack116)(ppcStack116,piStack124);
  }
  pcVar3 = ppcStack116[0x13];
  if (pcVar3 == FUN_00013aa0) {
    puVar16 = *(undefined4 **)(ppcStack116[1] + 0x34);
    (**(code **)(*piStack124 + 0xf4))(piStack124,*puVar16,puVar16[3]);
    cVar4 = (**(code **)(*piStack124 + 0x390))(piStack124);
    if (cVar4 != '\0') {
      (**(code **)(*piStack124 + 0x44))(piStack124);
    }
    (**(code **)(*piStack124 + 0x58))(piStack124,*puVar16);
    iVar5 = *piStack124;
    uVar10 = puVar16[4];
  }
  else {
    if (pcVar3 == FUN_00013a50) {
      func_0x00011b70(*(undefined4 *)(ppcStack116[1] + 0x34));
      goto LAB_00012f11;
    }
    if (pcVar3 == FUN_00013b20) {
      puVar16 = *(undefined4 **)(ppcStack116[1] + 0x34);
      iVar5 = *piStack124;
      uVar10 = puVar16[1];
    }
    else {
      if (pcVar3 != FUN_00013b40) goto LAB_00012f11;
      puVar16 = *(undefined4 **)(ppcStack116[1] + 0x34);
      iVar5 = *piStack124;
      uVar10 = puVar16[5];
    }
  }
  (**(code **)(iVar5 + 0x58))(piStack124,uVar10);
  func_0x00011b80(puVar16);
LAB_00012f11:
  *(undefined4 *)(ppcStack116[1] + 0x34) = 0;
  func_0x00011b80(ppcStack116[0xb]);
  ppcStack116[0xb] = (code *)0x0;
  func_0x00011b80(ppcStack116[10]);
  ppcStack116[10] = (code *)0x0;
  func_0x00011b80(ppcStack116[0xe]);
  ppcStack116[0xe] = (code *)0x0;
  func_0x00011b80(ppcStack116[0x10]);
  ppcStack116[0x10] = (code *)0x0;
  FUN_00015b00(ppcStack116[1]);
  iVar5 = func_0x00011b80(ppcStack116);
  return iVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00012c00(int param_1)

{
  byte bVar1;
  uint uVar2;
  code *pcVar3;
  char cVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int in_ECX;
  byte *in_EDX;
  undefined4 *puVar9;
  int *piStack44;
  code **ppcStack36;
  byte *pbStack28;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  uVar5 = 1;
  if (in_EDX != (byte *)0x0) {
    if (in_ECX == 0xff) {
      bVar1 = *in_EDX;
      pbStack28 = in_EDX;
      iVar8 = func_0x00011b40(&UNK_00017b28,in_EDX + 1,bVar1);
      if ((iVar8 == 0) || (iVar8 = func_0x00011b40(&UNK_00017b34,in_EDX + 1,bVar1), iVar8 == 0)) {
        iVar8 = FUN_00015a00(*(undefined4 *)(param_1 + 4),&pbStack28);
        if (iVar8 == 0) goto LAB_00012df3;
        uVar5 = 1;
        if (((pbStack28 != (byte *)0x0) && (*pbStack28 == 3)) && (pbStack28[1] == 1)) {
          iVar8 = (uint)pbStack28[3] * 0x100 + (uint)pbStack28[2];
          iVar7 = (uint)pbStack28[3] * 0x100 + 1 + (uint)pbStack28[2];
          if (iVar8 == 0) {
            iVar7 = iVar8;
          }
          uVar5 = 1;
          *(int *)(param_1 + 0x44) = iVar7;
        }
      }
      else {
        uVar5 = 1;
      }
    }
    else if (in_ECX == 0xfe) {
      ppcStack36 = (code **)(uint)*in_EDX;
      iVar8 = *(int *)(param_1 + 0x40);
      if (iVar8 == 0) {
        iVar7 = 0;
      }
      else {
        iVar7 = func_0x00011b50(iVar8);
      }
      iVar8 = FUN_00015cf0(iVar8,iVar7 + 1 + (int)ppcStack36,1);
      if (iVar8 == 0) {
        *(undefined4 *)(*(int *)(param_1 + 4) + 0x30) = 0x6d;
LAB_00012df3:
        uVar5 = 0;
      }
      else {
        func_0x00011b60(iVar8 + iVar7,in_EDX + 1,ppcStack36);
        *(undefined *)((int)ppcStack36 + iVar8 + iVar7) = 0;
        *(int *)(param_1 + 0x40) = iVar8;
        uVar5 = 1;
      }
    }
    else if (in_ECX == 0xf9) {
      iVar8 = *(int *)(param_1 + 0x28);
      iVar7 = *(int *)(*(int *)(param_1 + 4) + 0x10);
      ppcStack36 = (code **)(iVar7 * 3);
      iVar6 = FUN_00015ab0(*in_EDX,in_EDX + 1,iVar8 + iVar7 * 0xc);
      if (iVar6 == 0) goto LAB_00012df3;
      uVar2 = *(uint *)(iVar8 + 4 + iVar7 * 0xc);
      iVar6 = 100;
      if (1 < uVar2) {
        iVar6 = uVar2 * 10;
      }
      *(int *)(iVar8 + 4 + iVar7 * 0xc) = iVar6;
      uVar5 = 1;
    }
  }
  if (___stack_chk_guard == iStack24) {
    return uVar5;
  }
  uVar5 = func_0x00011af0();
  if (ppcStack36 == (code **)0x0) {
    return uVar5;
  }
  if (*ppcStack36 != (code *)0x0) {
    (**ppcStack36)(ppcStack36,piStack44);
  }
  pcVar3 = ppcStack36[0x13];
  if (pcVar3 == FUN_00013aa0) {
    puVar9 = *(undefined4 **)(ppcStack36[1] + 0x34);
    (**(code **)(*piStack44 + 0xf4))(piStack44,*puVar9,puVar9[3]);
    cVar4 = (**(code **)(*piStack44 + 0x390))(piStack44);
    if (cVar4 != '\0') {
      (**(code **)(*piStack44 + 0x44))(piStack44);
    }
    (**(code **)(*piStack44 + 0x58))(piStack44,*puVar9);
    iVar8 = *piStack44;
    uVar5 = puVar9[4];
  }
  else {
    if (pcVar3 == FUN_00013a50) {
      func_0x00011b70(*(undefined4 *)(ppcStack36[1] + 0x34));
      goto LAB_00012f11;
    }
    if (pcVar3 == FUN_00013b20) {
      puVar9 = *(undefined4 **)(ppcStack36[1] + 0x34);
      iVar8 = *piStack44;
      uVar5 = puVar9[1];
    }
    else {
      if (pcVar3 != FUN_00013b40) goto LAB_00012f11;
      puVar9 = *(undefined4 **)(ppcStack36[1] + 0x34);
      iVar8 = *piStack44;
      uVar5 = puVar9[5];
    }
  }
  (**(code **)(iVar8 + 0x58))(piStack44,uVar5);
  func_0x00011b80(puVar9);
LAB_00012f11:
  *(undefined4 *)(ppcStack36[1] + 0x34) = 0;
  func_0x00011b80(ppcStack36[0xb]);
  ppcStack36[0xb] = (code *)0x0;
  func_0x00011b80(ppcStack36[10]);
  ppcStack36[10] = (code *)0x0;
  func_0x00011b80(ppcStack36[0xe]);
  ppcStack36[0xe] = (code *)0x0;
  func_0x00011b80(ppcStack36[0x10]);
  ppcStack36[0x10] = (code *)0x0;
  FUN_00015b00(ppcStack36[1]);
  uVar5 = func_0x00011b80(ppcStack36);
  return uVar5;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_free(int *param_1,undefined4 param_2,code **param_3)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  
  if (param_3 == (code **)0x0) {
    return;
  }
  if (*param_3 != (code *)0x0) {
    (**param_3)(param_3,param_1);
  }
  pcVar1 = param_3[0x13];
  if (pcVar1 == FUN_00013aa0) {
    puVar5 = *(undefined4 **)(param_3[1] + 0x34);
    (**(code **)(*param_1 + 0xf4))(param_1,*puVar5,puVar5[3]);
    cVar2 = (**(code **)(*param_1 + 0x390))(param_1);
    if (cVar2 != '\0') {
      (**(code **)(*param_1 + 0x44))(param_1);
    }
    (**(code **)(*param_1 + 0x58))(param_1,*puVar5);
    iVar3 = *param_1;
    uVar4 = puVar5[4];
  }
  else {
    if (pcVar1 == FUN_00013a50) {
      func_0x00011b70(*(undefined4 *)(param_3[1] + 0x34));
      goto LAB_00012f11;
    }
    if (pcVar1 == FUN_00013b20) {
      puVar5 = *(undefined4 **)(param_3[1] + 0x34);
      iVar3 = *param_1;
      uVar4 = puVar5[1];
    }
    else {
      if (pcVar1 != FUN_00013b40) goto LAB_00012f11;
      puVar5 = *(undefined4 **)(param_3[1] + 0x34);
      iVar3 = *param_1;
      uVar4 = puVar5[5];
    }
  }
  (**(code **)(iVar3 + 0x58))(param_1,uVar4);
  func_0x00011b80(puVar5);
LAB_00012f11:
  *(undefined4 *)(param_3[1] + 0x34) = 0;
  func_0x00011b80(param_3[0xb]);
  param_3[0xb] = (code *)0x0;
  func_0x00011b80(param_3[10]);
  param_3[10] = (code *)0x0;
  func_0x00011b80(param_3[0xe]);
  param_3[0xe] = (code *)0x0;
  func_0x00011b80(param_3[0x10]);
  param_3[0x10] = (code *)0x0;
  FUN_00015b00(param_3[1]);
  func_0x00011b80(param_3);
  return;
}



void FUN_00012f80(int param_1)

{
  func_0x00011b80(*(undefined4 *)(param_1 + 0x2c));
  *(undefined4 *)(param_1 + 0x2c) = 0;
  func_0x00011b80(*(undefined4 *)(param_1 + 0x28));
  *(undefined4 *)(param_1 + 0x28) = 0;
  func_0x00011b80(*(undefined4 *)(param_1 + 0x38));
  *(undefined4 *)(param_1 + 0x38) = 0;
  func_0x00011b80(*(undefined4 *)(param_1 + 0x40));
  *(undefined4 *)(param_1 + 0x40) = 0;
  FUN_00015b00(*(undefined4 *)(param_1 + 4));
  func_0x00011b80(param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00013000(undefined2 *param_1,int param_2)

{
  uint *puVar1;
  undefined uVar2;
  byte bVar3;
  byte bVar4;
  undefined2 uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined2 *puVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iStack96;
  int iStack76;
  int iStack44;
  int iStack40;
  
  iVar6 = ___stack_chk_guard;
  iVar15 = *(int *)(param_2 + 4);
  if ((*(int *)(iVar15 + 0xc) == 0) || (*(int *)(*(int *)(param_2 + 0x28) + 8) != -1)) {
    func_0x00011b90(param_1,0,*(int *)(param_2 + 0x54) * *(int *)(iVar15 + 4) * 4);
  }
  else {
    iVar14 = *(int *)(*(int *)(iVar15 + 0xc) + 8);
    iVar16 = *(int *)(iVar15 + 8) * 3;
    uVar2 = *(undefined *)(iVar14 + 2 + iVar16);
    uVar5 = *(undefined2 *)(iVar14 + iVar16);
    puVar13 = param_1;
    if (0 < *(int *)(iVar15 + 4) * *(int *)(param_2 + 0x54)) {
      do {
        *(undefined *)((int)puVar13 + 3) = 0xff;
        *(undefined *)(puVar13 + 1) = uVar2;
        *puVar13 = uVar5;
        puVar13 = puVar13 + 2;
      } while (puVar13 < param_1 + *(int *)(*(int *)(param_2 + 4) + 4) * *(int *)(param_2 + 0x54) *
                                   2);
    }
  }
  if (___stack_chk_guard == iVar6) {
    return;
  }
  func_0x00011af0();
  iVar15 = *(int *)(iStack40 + 0x24);
  if (iVar15 == 0) goto LAB_000132e8;
  iVar6 = *(int *)(iStack40 + 4);
  iVar14 = *(int *)(iStack40 + 0x28);
  bVar3 = *(byte *)(iVar14 + -0xc + iVar15 * 0xc);
  bVar4 = *(byte *)(iVar14 + iVar15 * 0xc);
  iVar16 = *(int *)(iVar6 + 0x2c);
  iVar14 = *(int *)(iVar14 + 8 + iVar15 * 0xc);
  iVar11 = *(int *)(iStack40 + 0x2c);
  if ((bVar4 == 3 || bVar3 == 3) && (iVar11 == 0)) {
    iVar11 = func_0x00011ba0(*(int *)(iVar6 + 4) * *(int *)(iStack40 + 0x54),4);
    *(int *)(iStack40 + 0x2c) = iVar11;
    if (iVar11 == 0) {
      *(undefined4 *)(iVar6 + 0x30) = 0x6d;
      goto LAB_000132e8;
    }
  }
  iVar12 = iVar15 + -1;
  puVar1 = (uint *)(iVar16 + iVar12 * 0x18);
  iVar9 = iVar11;
  iVar10 = iStack44;
  if (iVar14 == -1) {
    uVar7 = *(uint *)(iVar16 + iVar15 * 0x18);
    uVar8 = *puVar1;
    if ((uVar8 < uVar7) ||
       (uVar7 + *(int *)(iVar16 + 8 + iVar15 * 0x18) < uVar8 + *(int *)(iVar16 + 8 + iVar12 * 0x18))
       ) goto LAB_00013207;
    uVar7 = *(uint *)(iVar16 + 4 + iVar15 * 0x18);
    uVar8 = *(uint *)(iVar16 + 4 + iVar12 * 0x18);
    if ((uVar8 < uVar7) ||
       (uVar7 + *(int *)(iVar16 + 0xc + iVar15 * 0x18) <
        uVar8 + *(int *)(iVar16 + 0xc + iVar12 * 0x18))) goto LAB_00013207;
  }
  else {
LAB_00013207:
    if ((bVar3 == 2) || ((iVar15 == 1 && (bVar3 == 3)))) {
      iVar15 = *(int *)(iVar16 + 0xc + iVar12 * 0x18);
      if (iVar15 != 0) {
        iVar14 = iStack44 + *(int *)(iVar16 + 4 + iVar12 * 0x18) * *(int *)(iStack40 + 0x54) * 4 +
                 *puVar1 * 4;
        do {
          func_0x00011b90(iVar14,0,*(int *)(iVar16 + 8 + iVar12 * 0x18) << 2);
          iVar14 = iVar14 + *(int *)(iStack40 + 0x54) * 4;
          iVar15 = iVar15 + -1;
        } while (iVar15 != 0);
      }
    }
    else {
      iVar9 = iStack44;
      iVar10 = iVar11;
      if ((byte)(bVar3 ^ 3 | bVar4 ^ 3) != 0) {
        iVar9 = iVar11;
        iVar10 = iStack44;
      }
    }
  }
  if (bVar4 == 3) {
    func_0x00011b60(iVar9,iVar10,*(int *)(iStack40 + 0x54) * *(int *)(iVar6 + 4) * 4);
  }
LAB_000132e8:
  iVar15 = *(int *)(iStack40 + 0x24);
  iVar6 = *(int *)(*(int *)(iStack40 + 4) + 0x2c);
  iStack76 = *(int *)(iVar6 + 0x14 + iVar15 * 0x18);
  if ((iStack76 == 0) && (iStack76 = *(int *)(*(int *)(iStack40 + 4) + 0xc), iStack76 == 0)) {
    iStack76 = FUN_00016250();
  }
  iVar14 = *(int *)(iStack40 + 0x38);
  if (iVar14 != 0) {
    iStack96 = iStack44 + *(int *)(iVar6 + 4 + iVar15 * 0x18) * *(int *)(iStack40 + 0x54) * 4 +
               *(int *)(iVar6 + iVar15 * 0x18) * 4;
    iVar16 = *(int *)(iVar6 + 8 + iVar15 * 0x18);
    iVar15 = *(int *)(iVar6 + 0xc + iVar15 * 0x18);
    uVar7 = *(uint *)(*(int *)(iStack40 + 0x28) + 8 + *(int *)(iStack40 + 0x24) * 0xc);
    iVar6 = *(int *)(iStack40 + 0x54) - iVar16;
    if (*(char *)(iStack40 + 0x60) == '\0') {
      if (uVar7 == 0xffffffff) {
        if (iVar15 != 0) {
          do {
            func_0x00011b90(iStack96,0xff,iVar16 * 4);
            if (iVar16 != 0) {
              iVar11 = 0;
              do {
                iVar9 = *(int *)(iStack76 + 8);
                iVar10 = (uint)*(byte *)(iVar14 + iVar11) * 3;
                *(undefined *)(iStack96 + 2 + iVar11 * 4) = *(undefined *)(iVar9 + 2 + iVar10);
                *(undefined2 *)(iStack96 + iVar11 * 4) = *(undefined2 *)(iVar9 + iVar10);
                iVar11 = iVar11 + 1;
              } while (iVar16 != iVar11);
              iVar14 = iVar14 + iVar16;
              iStack96 = iStack96 + iVar16 * 4;
            }
            iStack96 = iStack96 + iVar6 * 4;
            iVar15 = iVar15 + -1;
          } while (iVar15 != 0);
        }
      }
      else {
        for (; iVar15 != 0; iVar15 = iVar15 + -1) {
          if (iVar16 != 0) {
            iVar11 = 0;
            do {
              if (uVar7 != *(byte *)(iVar14 + iVar11)) {
                iVar9 = *(int *)(iStack76 + 8);
                iVar10 = (uint)*(byte *)(iVar14 + iVar11) * 3;
                *(undefined *)(iStack96 + 2 + iVar11 * 4) = *(undefined *)(iVar9 + 2 + iVar10);
                *(undefined2 *)(iStack96 + iVar11 * 4) = *(undefined2 *)(iVar9 + iVar10);
                *(undefined *)(iStack96 + 3 + iVar11 * 4) = 0xff;
              }
              iVar11 = iVar11 + 1;
            } while (iVar16 != iVar11);
            iVar14 = iVar14 + iVar16;
            iStack96 = iStack96 + iVar16 * 4;
          }
          iStack96 = iStack96 + iVar6 * 4;
        }
      }
    }
    else if (uVar7 == 0xffffffff) {
      for (; iVar15 != 0; iVar15 = iVar15 + -1) {
        if (iVar16 != 0) {
          iVar11 = 0;
          do {
            iVar9 = *(int *)(iStack76 + 8);
            iVar10 = (uint)*(byte *)(iVar14 + iVar11) * 3;
            *(undefined *)(iStack96 + 2 + iVar11 * 4) = *(undefined *)(iVar9 + 2 + iVar10);
            *(undefined2 *)(iStack96 + iVar11 * 4) = *(undefined2 *)(iVar9 + iVar10);
            iVar11 = iVar11 + 1;
          } while (iVar16 != iVar11);
          iVar14 = iVar14 + iVar16;
          iStack96 = iStack96 + iVar16 * 4;
        }
        iStack96 = iStack96 + iVar6 * 4;
      }
    }
    else {
      for (; iVar15 != 0; iVar15 = iVar15 + -1) {
        if (iVar16 != 0) {
          iVar11 = 0;
          do {
            if (uVar7 != *(byte *)(iVar14 + iVar11)) {
              iVar9 = *(int *)(iStack76 + 8);
              iVar10 = (uint)*(byte *)(iVar14 + iVar11) * 3;
              *(undefined *)(iStack96 + 2 + iVar11 * 4) = *(undefined *)(iVar9 + 2 + iVar10);
              *(undefined2 *)(iStack96 + iVar11 * 4) = *(undefined2 *)(iVar9 + iVar10);
            }
            iVar11 = iVar11 + 1;
          } while (iVar16 != iVar11);
          iVar14 = iVar14 + iVar16;
          iStack96 = iStack96 + iVar16 * 4;
        }
        iStack96 = iStack96 + iVar6 * 4;
      }
    }
  }
  return;
}



void FUN_000130e0(int param_1,int param_2)

{
  uint *puVar1;
  byte bVar2;
  byte bVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iStack48;
  int iStack28;
  
  iVar13 = *(int *)(param_2 + 0x24);
  if (iVar13 == 0) goto LAB_000132e8;
  iVar4 = *(int *)(param_2 + 4);
  iVar12 = *(int *)(param_2 + 0x28);
  bVar2 = *(byte *)(iVar12 + -0xc + iVar13 * 0xc);
  bVar3 = *(byte *)(iVar12 + iVar13 * 0xc);
  iVar5 = *(int *)(iVar4 + 0x2c);
  iVar12 = *(int *)(iVar12 + 8 + iVar13 * 0xc);
  iVar10 = *(int *)(param_2 + 0x2c);
  if ((bVar3 == 3 || bVar2 == 3) && (iVar10 == 0)) {
    iVar10 = func_0x00011ba0(*(int *)(iVar4 + 4) * *(int *)(param_2 + 0x54),4);
    *(int *)(param_2 + 0x2c) = iVar10;
    if (iVar10 == 0) {
      *(undefined4 *)(iVar4 + 0x30) = 0x6d;
      goto LAB_000132e8;
    }
  }
  iVar11 = iVar13 + -1;
  puVar1 = (uint *)(iVar5 + iVar11 * 0x18);
  iVar8 = iVar10;
  iVar9 = param_1;
  if (iVar12 == -1) {
    uVar6 = *(uint *)(iVar5 + iVar13 * 0x18);
    uVar7 = *puVar1;
    if ((uVar7 < uVar6) ||
       (uVar6 + *(int *)(iVar5 + 8 + iVar13 * 0x18) < uVar7 + *(int *)(iVar5 + 8 + iVar11 * 0x18)))
    goto LAB_00013207;
    uVar6 = *(uint *)(iVar5 + 4 + iVar13 * 0x18);
    uVar7 = *(uint *)(iVar5 + 4 + iVar11 * 0x18);
    if ((uVar7 < uVar6) ||
       (uVar6 + *(int *)(iVar5 + 0xc + iVar13 * 0x18) <
        uVar7 + *(int *)(iVar5 + 0xc + iVar11 * 0x18))) goto LAB_00013207;
  }
  else {
LAB_00013207:
    if ((bVar2 == 2) || ((iVar13 == 1 && (bVar2 == 3)))) {
      iVar13 = *(int *)(iVar5 + 0xc + iVar11 * 0x18);
      if (iVar13 != 0) {
        iVar12 = param_1 + *(int *)(iVar5 + 4 + iVar11 * 0x18) * *(int *)(param_2 + 0x54) * 4 +
                 *puVar1 * 4;
        do {
          func_0x00011b90(iVar12,0,*(int *)(iVar5 + 8 + iVar11 * 0x18) << 2);
          iVar12 = iVar12 + *(int *)(param_2 + 0x54) * 4;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
    }
    else {
      iVar8 = param_1;
      iVar9 = iVar10;
      if ((byte)(bVar2 ^ 3 | bVar3 ^ 3) != 0) {
        iVar8 = iVar10;
        iVar9 = param_1;
      }
    }
  }
  if (bVar3 == 3) {
    func_0x00011b60(iVar8,iVar9,*(int *)(param_2 + 0x54) * *(int *)(iVar4 + 4) * 4);
  }
LAB_000132e8:
  iVar13 = *(int *)(param_2 + 0x24);
  iVar4 = *(int *)(*(int *)(param_2 + 4) + 0x2c);
  iStack28 = *(int *)(iVar4 + 0x14 + iVar13 * 0x18);
  if ((iStack28 == 0) && (iStack28 = *(int *)(*(int *)(param_2 + 4) + 0xc), iStack28 == 0)) {
    iStack28 = FUN_00016250();
  }
  iVar12 = *(int *)(param_2 + 0x38);
  if (iVar12 != 0) {
    iStack48 = param_1 + *(int *)(iVar4 + 4 + iVar13 * 0x18) * *(int *)(param_2 + 0x54) * 4 +
               *(int *)(iVar4 + iVar13 * 0x18) * 4;
    iVar5 = *(int *)(iVar4 + 8 + iVar13 * 0x18);
    iVar13 = *(int *)(iVar4 + 0xc + iVar13 * 0x18);
    uVar6 = *(uint *)(*(int *)(param_2 + 0x28) + 8 + *(int *)(param_2 + 0x24) * 0xc);
    iVar4 = *(int *)(param_2 + 0x54) - iVar5;
    if (*(char *)(param_2 + 0x60) == '\0') {
      if (uVar6 == 0xffffffff) {
        if (iVar13 != 0) {
          do {
            func_0x00011b90(iStack48,0xff,iVar5 * 4);
            if (iVar5 != 0) {
              iVar10 = 0;
              do {
                iVar8 = *(int *)(iStack28 + 8);
                iVar9 = (uint)*(byte *)(iVar12 + iVar10) * 3;
                *(undefined *)(iStack48 + 2 + iVar10 * 4) = *(undefined *)(iVar8 + 2 + iVar9);
                *(undefined2 *)(iStack48 + iVar10 * 4) = *(undefined2 *)(iVar8 + iVar9);
                iVar10 = iVar10 + 1;
              } while (iVar5 != iVar10);
              iVar12 = iVar12 + iVar5;
              iStack48 = iStack48 + iVar5 * 4;
            }
            iStack48 = iStack48 + iVar4 * 4;
            iVar13 = iVar13 + -1;
          } while (iVar13 != 0);
        }
      }
      else {
        for (; iVar13 != 0; iVar13 = iVar13 + -1) {
          if (iVar5 != 0) {
            iVar10 = 0;
            do {
              if (uVar6 != *(byte *)(iVar12 + iVar10)) {
                iVar8 = *(int *)(iStack28 + 8);
                iVar9 = (uint)*(byte *)(iVar12 + iVar10) * 3;
                *(undefined *)(iStack48 + 2 + iVar10 * 4) = *(undefined *)(iVar8 + 2 + iVar9);
                *(undefined2 *)(iStack48 + iVar10 * 4) = *(undefined2 *)(iVar8 + iVar9);
                *(undefined *)(iStack48 + 3 + iVar10 * 4) = 0xff;
              }
              iVar10 = iVar10 + 1;
            } while (iVar5 != iVar10);
            iVar12 = iVar12 + iVar5;
            iStack48 = iStack48 + iVar5 * 4;
          }
          iStack48 = iStack48 + iVar4 * 4;
        }
      }
    }
    else if (uVar6 == 0xffffffff) {
      for (; iVar13 != 0; iVar13 = iVar13 + -1) {
        if (iVar5 != 0) {
          iVar10 = 0;
          do {
            iVar8 = *(int *)(iStack28 + 8);
            iVar9 = (uint)*(byte *)(iVar12 + iVar10) * 3;
            *(undefined *)(iStack48 + 2 + iVar10 * 4) = *(undefined *)(iVar8 + 2 + iVar9);
            *(undefined2 *)(iStack48 + iVar10 * 4) = *(undefined2 *)(iVar8 + iVar9);
            iVar10 = iVar10 + 1;
          } while (iVar5 != iVar10);
          iVar12 = iVar12 + iVar5;
          iStack48 = iStack48 + iVar5 * 4;
        }
        iStack48 = iStack48 + iVar4 * 4;
      }
    }
    else {
      for (; iVar13 != 0; iVar13 = iVar13 + -1) {
        if (iVar5 != 0) {
          iVar10 = 0;
          do {
            if (uVar6 != *(byte *)(iVar12 + iVar10)) {
              iVar8 = *(int *)(iStack28 + 8);
              iVar9 = (uint)*(byte *)(iVar12 + iVar10) * 3;
              *(undefined *)(iStack48 + 2 + iVar10 * 4) = *(undefined *)(iVar8 + 2 + iVar9);
              *(undefined2 *)(iStack48 + iVar10 * 4) = *(undefined2 *)(iVar8 + iVar9);
            }
            iVar10 = iVar10 + 1;
          } while (iVar5 != iVar10);
          iVar12 = iVar12 + iVar5;
          iStack48 = iStack48 + iVar5 * 4;
        }
        iStack48 = iStack48 + iVar4 * 4;
      }
    }
  }
  return;
}



undefined4 FUN_00013650(int param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  
  iVar1 = *(int *)(param_1 + 0x24);
  uVar3 = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4 + iVar1 * 0xc);
  *(uint *)(param_1 + 0x24) = iVar1 + 1U;
  if (*(uint *)(*(int *)(param_1 + 4) + 0x10) <= iVar1 + 1U) {
    if ((*(uint *)(param_1 + 0x44) == 0) ||
       (uVar2 = *(int *)(param_1 + 0x48) + 1, uVar2 < *(uint *)(param_1 + 0x44))) {
      iVar1 = (**(code **)(param_1 + 0x4c))(param_1);
      if (iVar1 != 0) {
        return 0;
      }
      iVar1 = 0;
      if (*(int *)(param_1 + 0x44) != 0) {
        *(int *)(param_1 + 0x48) = *(int *)(param_1 + 0x48) + 1;
      }
    }
    else {
      *(uint *)(param_1 + 0x48) = uVar2;
      uVar3 = 0;
    }
    *(int *)(param_1 + 0x24) = iVar1;
  }
  return uVar3;
}



undefined4 FUN_000136d0(undefined4 param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  
  FUN_000130e0(param_1,param_2);
  iVar1 = *(int *)(param_2 + 0x24);
  uVar3 = *(undefined4 *)(*(int *)(param_2 + 0x28) + 4 + iVar1 * 0xc);
  *(uint *)(param_2 + 0x24) = iVar1 + 1U;
  if (*(uint *)(*(int *)(param_2 + 4) + 0x10) <= iVar1 + 1U) {
    if ((*(uint *)(param_2 + 0x44) == 0) ||
       (uVar2 = *(int *)(param_2 + 0x48) + 1, uVar2 < *(uint *)(param_2 + 0x44))) {
      iVar1 = (**(code **)(param_2 + 0x4c))(param_2);
      if (iVar1 != 0) {
        return 0;
      }
      iVar1 = 0;
      if (*(int *)(param_2 + 0x44) != 0) {
        *(int *)(param_2 + 0x48) = *(int *)(param_2 + 0x48) + 1;
      }
    }
    else {
      *(uint *)(param_2 + 0x48) = uVar2;
      uVar3 = 0;
    }
    *(int *)(param_2 + 0x24) = iVar1;
  }
  return uVar3;
}



// WARNING: Removing unreachable block (ram,0x000138c2)
// WARNING: Removing unreachable block (ram,0x000138e1)
// WARNING: Removing unreachable block (ram,0x000138f0)
// WARNING: Removing unreachable block (ram,0x000138f3)
// WARNING: Removing unreachable block (ram,0x00013904)
// WARNING: Removing unreachable block (ram,0x00013918)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00013760(int *param_1,int param_2,undefined *param_3)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puStack544;
  undefined auStack534 [255];
  undefined auStack279 [255];
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  piVar2 = (int *)func_0x00011bb0();
  iVar3 = 2;
  if (*piVar2 != 0xc) {
    iVar3 = param_2;
  }
  if (iVar3 == 0) {
    func_0x00011b90(auStack279,0,0xff);
    func_0x00011bc0(auStack279,param_3,0xff);
    iVar3 = func_0x00011bd0(*piVar2,auStack534,0xff);
    puVar4 = &UNK_00017b7a;
    if (iVar3 == 0) {
      func_0x00011bc0(auStack279,auStack534,0xff);
    }
    puStack544 = auStack279;
  }
  else {
    puStack544 = param_3;
    if (iVar3 == 2) {
      puVar4 = &UNK_00017b40;
    }
    else if (iVar3 == 3) {
      puVar4 = &UNK_00017b5b;
    }
    else {
      puVar4 = &UNK_00017b7a;
    }
  }
  cVar1 = (**(code **)(*param_1 + 0x390))(param_1);
  if ((cVar1 != '\x01') && (iVar3 = (**(code **)(*param_1 + 0x18))(param_1,puVar4), iVar3 != 0)) {
    (**(code **)(*param_1 + 0x38))(param_1,iVar3,puStack544);
  }
  if (___stack_chk_guard == iStack24) {
    return ___stack_chk_guard;
  }
  func_0x00011af0();
  return 0;
}



undefined4 FUN_000138a0(int param_1,int *param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  undefined *puVar5;
  
  if (param_1 == 0) {
    piVar2 = (int *)func_0x00011bb0();
    iVar3 = *piVar2;
    cVar1 = (**(code **)(*param_2 + 0x390))(param_2);
    uVar4 = 1;
    if (cVar1 != '\x01') {
      puVar5 = &UNK_00017b5b;
      if (iVar3 == 0xc) {
        puVar5 = &UNK_00017b40;
      }
      iVar3 = (**(code **)(*param_2 + 0x18))(param_2,puVar5);
      if (iVar3 != 0) {
        (**(code **)(*param_2 + 0x38))(param_2,iVar3,&UNK_00017b95);
      }
      uVar4 = 1;
    }
  }
  else {
    uVar4 = 0;
  }
  return uVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00013930(undefined4 param_1,int *param_2,char param_3)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  int iVar5;
  int unaff_ESI;
  undefined auStack279 [255];
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  piVar3 = param_2;
  cVar1 = (**(code **)(*param_2 + 0x390))(param_2);
  if (((cVar1 != '\x01') &&
      (piVar3 = param_2, unaff_ESI = (**(code **)(*param_2 + 0x18))(param_2,&UNK_00017baa),
      unaff_ESI != 0)) &&
     (piVar3 = param_2,
     iVar2 = (**(code **)(*param_2 + 0x84))(param_2,unaff_ESI,&UNK_00017bce,&UNK_00017bd5),
     iVar2 != 0)) {
    piVar3 = (int *)0x0;
    if (param_3 != '\0') {
      puVar4 = (undefined4 *)func_0x00011bb0();
      iVar5 = func_0x00011bd0(*puVar4,auStack279,0xff);
      piVar3 = (int *)0x0;
      if (iVar5 == 0) {
        piVar3 = (int *)(**(code **)(*param_2 + 0x29c))(param_2,auStack279);
      }
    }
    iVar2 = (**(code **)(*param_2 + 0x70))(param_2,unaff_ESI,iVar2,param_1,piVar3);
    if (iVar2 != 0) {
      (**(code **)(*param_2 + 0x34))(param_2,iVar2);
      piVar3 = param_2;
    }
  }
  if (___stack_chk_guard != iStack24) {
    func_0x00011af0();
    iVar2 = func_0x00011be0(*(undefined4 *)(_memcpy + 0x34),_dup,0,&LAB_00013a5d,piVar3,unaff_ESI,
                            &__DT_PLTGOT,&stack0xfffffffc);
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      *(undefined4 *)(_memcpy + 0x30) = 0x3ec;
      iVar2 = -1;
    }
    return iVar2;
  }
  return ___stack_chk_guard;
}



undefined4 FUN_00013a50(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = func_0x00011be0(*(undefined4 *)(*(int *)(param_1 + 4) + 0x34),
                          *(undefined4 *)(param_1 + 0x30),0,&LAB_00013a5d);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    *(undefined4 *)(*(int *)(param_1 + 4) + 0x30) = 0x3ec;
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



undefined4 FUN_00013aa0(int param_1)

{
  undefined4 *puVar1;
  char cVar2;
  int *piVar3;
  
  puVar1 = *(undefined4 **)(*(int *)(param_1 + 4) + 0x34);
  piVar3 = (int *)FUN_00016080();
  puVar1[5] = 0;
  if (piVar3 != (int *)0x0) {
    (**(code **)(*piVar3 + 0xf4))(piVar3,*puVar1,puVar1[2]);
    cVar2 = (**(code **)(*piVar3 + 0x390))(piVar3);
    if (cVar2 == '\0') {
      return 0;
    }
    (**(code **)(*piVar3 + 0x44))(piVar3);
  }
  *(undefined4 *)(*(int *)(param_1 + 4) + 0x30) = 0x3ec;
  return 0xffffffff;
}



undefined4 FUN_00013b20(int param_1)

{
  **(undefined4 **)(*(int *)(param_1 + 4) + 0x34) = *(undefined4 *)(param_1 + 0x30);
  return 0;
}



undefined4 FUN_00013b40(int param_1)

{
  **(undefined8 **)(*(int *)(param_1 + 4) + 0x34) = *(undefined8 *)(param_1 + 0x30);
  return 0;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8
Java_pl_droidsonroids_gif_GifInfoHandle_openFile(int *param_1,undefined4 param_2,int *param_3)

{
  char cVar1;
  undefined *puVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  int *piVar6;
  uint uVar7;
  int iVar8;
  undefined4 extraout_EDX;
  int iVar9;
  undefined8 uVar10;
  int iStack252;
  undefined4 uStack248;
  undefined *puStack244;
  undefined auStack240 [16];
  code *pcStack224;
  undefined4 uStack220;
  undefined4 uStack216;
  int iStack200;
  undefined *puStack196;
  int *piStack192;
  code *pcStack188;
  undefined **ppuStack184;
  undefined *puStack180;
  int *piStack172;
  int *piStack164;
  undefined auStack160 [16];
  code *pcStack144;
  uint uStack140;
  uint uStack136;
  undefined auStack120 [44];
  uint uStack76;
  int iStack24;
  
  puStack180 = &LAB_00013b74;
  piStack164 = (int *)&__stack_chk_guard;
  iStack24 = ___stack_chk_guard;
  iVar9 = 0;
  pcStack188 = (code *)param_1;
  piStack192 = param_3;
  puStack196 = (undefined *)0x13b9f;
  cVar1 = FUN_000138a0();
  iVar8 = 0;
  piVar3 = param_3;
  if (cVar1 == '\0') {
    ppuStack184 = (undefined **)0x0;
    pcStack188 = (code *)param_3;
    piStack192 = param_1;
    puStack196 = (undefined *)0x13bc3;
    puVar2 = (undefined *)(**(code **)(*param_1 + 0x2a4))();
    if (puVar2 == (undefined *)0x0) {
      ppuStack184 = (undefined **)&UNK_00017bec;
      pcStack188 = (code *)0x1;
      piStack192 = param_1;
      puStack196 = (undefined *)0x13cb4;
      FUN_00013760();
      param_1 = param_3;
    }
    else {
      pcStack188 = (code *)&UNK_00017c05;
      puStack196 = (undefined *)0x13be0;
      piStack192 = (int *)puVar2;
      piVar3 = (int *)func_0x00011bf0();
      if (piVar3 != (int *)0x0) {
        pcStack188 = (code *)param_3;
        piStack192 = param_1;
        puStack196 = (undefined *)0x13c02;
        ppuStack184 = (undefined **)puVar2;
        (**(code **)(*param_1 + 0x2a8))();
        pcStack188 = (code *)auStack120;
        puStack196 = (undefined *)0x13c10;
        piStack192 = (int *)puVar2;
        iVar9 = func_0x00011c00();
        uStack140 = uStack76 | ~-(uint)(iVar9 == 0);
        uStack136 = ~-(uint)(iVar9 == 0) | (int)uStack76 >> 0x1f;
        ppuStack184 = (undefined **)(auStack160 + 4);
        auStack160 = ZEXT816(0);
        pcStack144 = FUN_00013a50;
        pcStack188 = FUN_00014920;
        puStack196 = (undefined *)0x13c56;
        piStack192 = piVar3;
        uVar4 = FUN_00014960();
        auStack160 = CONCAT124(auStack160._4_12_,uVar4);
        puStack196 = (undefined *)0x13c66;
        piStack192 = piVar3;
        iVar9 = func_0x00011c10();
        auStack160 = CONCAT412(iVar9 >> 0x1f,CONCAT48(iVar9,auStack160._0_8_));
        piStack192 = (int *)auStack160;
        pcStack188 = (code *)param_1;
        puStack196 = (undefined *)0x13c84;
        iVar9 = FUN_00015d50();
        if (iVar9 == 0) {
          puStack196 = (undefined *)0x13c96;
          piStack192 = piVar3;
          func_0x00011b70();
        }
        iVar8 = iVar9 >> 0x1f;
        goto LAB_00013ce0;
      }
      ppuStack184 = (undefined **)0x1;
      pcStack188 = (code *)param_1;
      piStack192 = (int *)0x65;
      puStack196 = (undefined *)0x13cc6;
      FUN_00013930();
      pcStack188 = (code *)param_3;
      piStack192 = param_1;
      puStack196 = &LAB_00013cd9;
      ppuStack184 = (undefined **)puVar2;
      (**(code **)(*param_1 + 0x2a8))();
    }
    iVar9 = 0;
    iVar8 = 0;
    piVar3 = param_1;
  }
LAB_00013ce0:
  if (*piStack164 == iStack24) {
    return CONCAT44(iVar8,iVar9);
  }
  puStack180 = (undefined *)0x13cfe;
  func_0x00011af0();
  iStack200 = ___stack_chk_guard;
  iVar8 = 0;
  piStack192 = piVar3;
  pcStack188 = (code *)iVar9;
  ppuStack184 = &__DT_PLTGOT;
  puStack180 = &stack0xfffffffc;
  cVar1 = FUN_000138a0(piStack164,piStack172);
  iVar9 = 0;
  if (cVar1 == '\0') {
    puVar5 = (undefined4 *)func_0x00011c20(0xc);
    puStack244 = &__stack_chk_guard;
    if (puVar5 == (undefined4 *)0x0) {
      puVar2 = &UNK_00017c08;
      uVar4 = 2;
    }
    else {
      iVar9 = (**(code **)(*piStack172 + 0x54))(piStack172,piStack164);
      puVar5[1] = iVar9;
      if (iVar9 != 0) {
        uStack220 = (**(code **)(*piStack172 + 0x2ac))(piStack172,iVar9);
        puVar5[2] = uStack220;
        *puVar5 = 0;
        auStack240 = ZEXT816(0);
        pcStack224 = FUN_00013b20;
        uStack216 = 0;
        uVar4 = FUN_00014960(puVar5,FUN_00013e70,auStack240 + 4);
        auStack240 = CONCAT124(auStack240._4_12_,uVar4);
        auStack240 = ZEXT1216(CONCAT48(*puVar5,auStack240._0_8_));
        iVar8 = FUN_00015d50(auStack240,piStack172);
        if (iVar8 == 0) {
          (**(code **)(*piStack172 + 0x58))(piStack172,puVar5[1]);
          func_0x00011b80(puVar5);
        }
        iVar9 = iVar8 >> 0x1f;
        goto LAB_00013e4c;
      }
      func_0x00011b80(puVar5);
      puVar2 = &UNK_00017c29;
      uVar4 = 1;
    }
    FUN_00013760(piStack172,uVar4,puVar2);
    iVar8 = 0;
    iVar9 = 0;
  }
LAB_00013e4c:
  if (___stack_chk_guard != iStack200) {
    func_0x00011af0();
    piVar3 = *(int **)(iStack252 + 0x34);
    uVar10 = FUN_00016080();
    uVar4 = (undefined4)((ulonglong)uVar10 >> 0x20);
    piVar6 = (int *)uVar10;
    if (piVar6 == (int *)0x0) {
      uVar7 = 0;
    }
    else {
      iVar9 = *piVar3;
      uVar7 = piVar3[2];
      if (uVar7 < ((uint)puStack244 & 0xff) + iVar9) {
        uVar7 = uVar7 - iVar9;
      }
      else {
        uVar7 = uVar7 & 0xffffff00 | (uint)puStack244 & 0xff;
      }
      (**(code **)(*piVar6 + 800))(piVar6,piVar3[1],iVar9,uVar7 & 0xff,uStack248);
      *piVar3 = *piVar3 + (uVar7 & 0xff);
      uVar4 = extraout_EDX;
    }
    return CONCAT44(uVar4,uVar7);
  }
  return CONCAT44(iVar9,iVar8);
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8
Java_pl_droidsonroids_gif_GifInfoHandle_openByteArray
          (int *param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  undefined4 extraout_EDX;
  int iVar8;
  undefined8 uVar9;
  undefined *puVar10;
  int iStack76;
  undefined4 uStack72;
  undefined *puStack68;
  undefined auStack64 [16];
  code *pcStack48;
  undefined4 uStack44;
  undefined4 uStack40;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  iVar8 = 0;
  cVar2 = FUN_000138a0(param_3,param_1);
  iVar7 = 0;
  if (cVar2 == '\0') {
    puVar3 = (undefined4 *)func_0x00011c20(0xc);
    puStack68 = &__stack_chk_guard;
    if (puVar3 == (undefined4 *)0x0) {
      puVar10 = &UNK_00017c08;
      uVar4 = 2;
    }
    else {
      iVar8 = (**(code **)(*param_1 + 0x54))(param_1,param_3);
      puVar3[1] = iVar8;
      if (iVar8 != 0) {
        uStack44 = (**(code **)(*param_1 + 0x2ac))(param_1,iVar8);
        puVar3[2] = uStack44;
        *puVar3 = 0;
        auStack64 = ZEXT816(0);
        pcStack48 = FUN_00013b20;
        uStack40 = 0;
        uVar4 = FUN_00014960(puVar3,FUN_00013e70,auStack64 + 4);
        auStack64 = CONCAT124(auStack64._4_12_,uVar4);
        auStack64 = ZEXT1216(CONCAT48(*puVar3,auStack64._0_8_));
        iVar8 = FUN_00015d50(auStack64,param_1);
        if (iVar8 == 0) {
          (**(code **)(*param_1 + 0x58))(param_1,puVar3[1]);
          func_0x00011b80(puVar3);
        }
        iVar7 = iVar8 >> 0x1f;
        goto LAB_00013e4c;
      }
      func_0x00011b80(puVar3);
      puVar10 = &UNK_00017c29;
      uVar4 = 1;
    }
    FUN_00013760(param_1,uVar4,puVar10);
    iVar8 = 0;
    iVar7 = 0;
  }
LAB_00013e4c:
  if (___stack_chk_guard != iStack24) {
    func_0x00011af0();
    piVar1 = *(int **)(iStack76 + 0x34);
    uVar9 = FUN_00016080();
    uVar4 = (undefined4)((ulonglong)uVar9 >> 0x20);
    piVar5 = (int *)uVar9;
    if (piVar5 == (int *)0x0) {
      uVar6 = 0;
    }
    else {
      iVar8 = *piVar1;
      uVar6 = piVar1[2];
      if (uVar6 < ((uint)puStack68 & 0xff) + iVar8) {
        uVar6 = uVar6 - iVar8;
      }
      else {
        uVar6 = uVar6 & 0xffffff00 | (uint)puStack68 & 0xff;
      }
      (**(code **)(*piVar5 + 800))(piVar5,piVar1[1],iVar8,uVar6 & 0xff,uStack72);
      *piVar1 = *piVar1 + (uVar6 & 0xff);
      uVar4 = extraout_EDX;
    }
    return CONCAT44(uVar4,uVar6);
  }
  return CONCAT44(iVar7,iVar8);
}



uint FUN_00013e70(int param_1,undefined4 param_2,byte param_3)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  
  piVar1 = *(int **)(param_1 + 0x34);
  piVar3 = (int *)FUN_00016080();
  if (piVar3 == (int *)0x0) {
    uVar4 = 0;
  }
  else {
    iVar2 = *piVar1;
    uVar4 = piVar1[2];
    if (uVar4 < (uint)param_3 + iVar2) {
      uVar4 = uVar4 - iVar2;
    }
    else {
      uVar4 = uVar4 & 0xffffff00 | (uint)param_3;
    }
    (**(code **)(*piVar3 + 800))(piVar3,piVar1[1],iVar2,uVar4 & 0xff,param_2);
    *piVar1 = *piVar1 + (uVar4 & 0xff);
  }
  return uVar4;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8
Java_pl_droidsonroids_gif_GifInfoHandle_openDirectByteBuffer
          (int *param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  char cVar4;
  uint uVar5;
  undefined8 *puVar6;
  undefined4 uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  undefined4 extraout_EDX;
  int iStack72;
  undefined auStack64 [16];
  code *pcStack48;
  undefined8 uStack44;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  uVar5 = (**(code **)(*param_1 + 0x398))(param_1,param_3);
  uStack44 = (**(code **)(*param_1 + 0x39c))(param_1,param_3);
  iVar11 = (int)((ulonglong)uStack44 >> 0x20);
  iVar8 = (int)uStack44;
  if ((uVar5 == 0) ||
     (iVar2 = -iVar11,
     (SBORROW4(iVar2,(uint)(iVar8 != 0)) != false) == (int)(iVar2 - (uint)(iVar8 != 0)) < 0)) {
    iVar8 = 0;
    cVar4 = FUN_000138a0(param_3,param_1);
    iVar11 = 0;
    if (cVar4 == '\0') {
      FUN_00013930(0x3ed,param_1,0);
      iVar8 = 0;
      iVar11 = 0;
    }
  }
  else {
    puVar6 = (undefined8 *)func_0x00011c20(0x18);
    iStack72 = iVar8;
    if (puVar6 == (undefined8 *)0x0) {
      FUN_00013760(param_1,2,&UNK_00017c08);
      iVar8 = 0;
      iVar11 = 0;
    }
    else {
      uVar7 = (**(code **)(*param_1 + 0x54))(param_1,param_3);
      *(undefined4 *)((int)puVar6 + 0x14) = uVar7;
      *(uint *)(puVar6 + 1) = uVar5;
      auStack64 = ZEXT816(0);
      pcStack48 = FUN_00013b40;
      *(int *)(puVar6 + 2) = iVar11;
      *(int *)((int)puVar6 + 0xc) = iVar8;
      *(undefined4 *)((int)puVar6 + 4) = 0;
      *(undefined4 *)puVar6 = 0;
      uVar7 = FUN_00014960(puVar6,FUN_00014090,auStack64 + 4);
      auStack64 = CONCAT124(auStack64._4_12_,uVar7);
      auStack64 = CONCAT88(*puVar6,auStack64._0_8_);
      iVar8 = FUN_00015d50(auStack64,param_1);
      if (iVar8 == 0) {
        func_0x00011b80(puVar6);
      }
      iVar11 = iVar8 >> 0x1f;
    }
  }
  if (___stack_chk_guard != iStack24) {
    func_0x00011af0();
    puVar3 = _eventfd;
    uVar1 = *_eventfd;
    uVar5 = uVar5 & 0xff;
    iVar11 = _eventfd[1] + (uint)CARRY4(uVar1,uVar5);
    uVar10 = (uint)(_eventfd[3] < uVar1 + uVar5);
    iVar8 = _eventfd[4] - iVar11;
    uVar9 = _eventfd[3] - uVar1;
    if ((SBORROW4(_eventfd[4],iVar11) != SBORROW4(iVar8,uVar10)) == (int)(iVar8 - uVar10) < 0) {
      uVar9 = uVar5;
    }
    uVar10 = uVar9 & 0xff;
    func_0x00011b60(iStack72,uVar1 + _eventfd[2],uVar10);
    uVar5 = *puVar3;
    *puVar3 = *puVar3 + uVar10;
    puVar3[1] = puVar3[1] + (uint)CARRY4(uVar5,uVar10);
    return CONCAT44(extraout_EDX,uVar9);
  }
  return CONCAT44(iVar11,iVar8);
}



uint FUN_00014090(int param_1,undefined4 param_2,byte param_3)

{
  uint *puVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  
  puVar1 = *(uint **)(param_1 + 0x34);
  uVar2 = *puVar1;
  uVar4 = (uint)param_3;
  iVar7 = puVar1[1] + (uint)CARRY4(uVar2,uVar4);
  uVar6 = (uint)(puVar1[3] < uVar2 + uVar4);
  iVar3 = puVar1[4] - iVar7;
  uVar5 = puVar1[3] - uVar2;
  if ((SBORROW4(puVar1[4],iVar7) != SBORROW4(iVar3,uVar6)) == (int)(iVar3 - uVar6) < 0) {
    uVar5 = uVar4;
  }
  uVar6 = uVar5 & 0xff;
  func_0x00011b60(param_2,uVar2 + puVar1[2],uVar6);
  uVar2 = *puVar1;
  *puVar1 = *puVar1 + uVar6;
  puVar1[1] = puVar1[1] + (uint)CARRY4(uVar2,uVar6);
  return uVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8
Java_pl_droidsonroids_gif_GifInfoHandle_openStream
          (int *param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  undefined4 *puVar2;
  uint uVar3;
  char cVar4;
  int *piVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint extraout_ECX_02;
  undefined8 uVar10;
  uint uStack124;
  uint uStack116;
  undefined *puVar11;
  int iStack76;
  int iStack72;
  int *piStack68;
  undefined8 uStack56;
  undefined8 uStack48;
  undefined8 uStack40;
  undefined4 uStack32;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  piVar5 = (int *)func_0x00011c20(0x1c);
  if (piVar5 == (int *)0x0) {
    puVar11 = &UNK_00017c08;
    uVar6 = 2;
LAB_0001434f:
    FUN_00013760(param_1,uVar6,puVar11);
LAB_00014354:
    iVar7 = 0;
    iVar8 = 0;
  }
  else {
    pcVar1 = *(code **)(*param_1 + 0x54);
    uVar6 = (**(code **)(*param_1 + 0x2c0))(param_1,0x2000);
    iVar7 = (*pcVar1)(param_1,uVar6);
    piVar5[4] = iVar7;
    if (iVar7 == 0) {
      func_0x00011b80(piVar5);
      puVar11 = &UNK_00017c08;
      uVar6 = 2;
LAB_000143bf:
      FUN_00013760(param_1,uVar6,puVar11);
    }
    else {
      iVar7 = (**(code **)(*param_1 + 0x7c))(param_1,param_3);
      piStack68 = piVar5;
      if (iVar7 == 0) {
        func_0x00011b80(piVar5);
        (**(code **)(*param_1 + 0x58))(param_1,piVar5[4]);
        puVar11 = &UNK_00017c29;
        uVar6 = 1;
        goto LAB_000143bf;
      }
      iStack72 = (**(code **)(*param_1 + 0x84))(param_1,iVar7,&UNK_00017c3d,&UNK_00017c42);
      iVar8 = (**(code **)(*param_1 + 0x84))(param_1,iVar7,&UNK_00017c47,&UNK_00017c4c);
      piVar5[1] = iVar8;
      iStack76 = (**(code **)(*param_1 + 0x84))(param_1,iVar7,&UNK_00017c54,&UNK_00017c5a);
      piVar5[2] = iStack76;
      iVar7 = (**(code **)(*param_1 + 0x84))(param_1,iVar7,&UNK_00017c5e,&UNK_00017c5a);
      piVar5[3] = iVar7;
      if ((((iStack72 != 0) && (iVar8 != 0)) && (iVar7 != 0)) && (iStack76 != 0)) {
        iVar7 = (**(code **)(*param_1 + 0x54))(param_1,param_3);
        *piVar5 = iVar7;
        if (iVar7 == 0) {
          func_0x00011b80(piVar5);
          (**(code **)(*param_1 + 0x58))(param_1,piVar5[4]);
          puVar11 = &UNK_00017c29;
          uVar6 = 1;
          goto LAB_0001434f;
        }
        uStack32 = uRam0001adf4;
        uStack40 = uRam0001adec;
        uStack48 = uRam0001ade4;
        uStack56 = _DAT_0001addc;
        piVar5[5] = 0;
        *(undefined *)(piVar5 + 6) = 0;
        uVar9 = FUN_00014960(piVar5,FUN_00014440,(int)&uStack56 + 4);
        uStack56 = uStack56 & 0xffffffff00000000 | (ulonglong)uVar9;
        (**(code **)(*param_1 + 0xf4))(param_1,param_3,iStack72,0x7fffffff);
        cVar4 = (**(code **)(*param_1 + 0x390))(param_1);
        if (cVar4 != '\0') {
          (**(code **)(*param_1 + 0x58))(param_1,*piVar5);
          (**(code **)(*param_1 + 0x58))(param_1,piVar5[4]);
          func_0x00011b80(piVar5);
          goto LAB_00014354;
        }
        iVar7 = FUN_00015d50(&uStack56,param_1);
        *(undefined *)(piVar5 + 6) = 1;
        piVar5[5] = 0;
        iVar8 = iVar7 >> 0x1f;
        goto LAB_000143ce;
      }
      func_0x00011b80(piVar5);
      (**(code **)(*param_1 + 0x58))(param_1,piVar5[4]);
    }
    iVar7 = 0;
    iVar8 = 0;
  }
LAB_000143ce:
  if (___stack_chk_guard == iStack24) {
    return CONCAT44(iVar8,iVar7);
  }
  func_0x00011af0();
  puVar2 = *(undefined4 **)(iStack76 + 0x34);
  uVar10 = FUN_00016080();
  uVar6 = (undefined4)((ulonglong)uVar10 >> 0x20);
  piVar5 = (int *)uVar10;
  if (piVar5 != (int *)0x0) {
    uVar10 = (**(code **)(*piVar5 + 0x364))(piVar5,*puVar2);
    uVar6 = (undefined4)((ulonglong)uVar10 >> 0x20);
    if ((int)uVar10 == 0) {
      uStack124 = (uint)piStack68 & 0xff;
      uStack116 = extraout_ECX & 0xffffff00 | uStack124;
      iVar7 = puVar2[5];
      if (iVar7 == 0) {
        uVar9 = 0x2000;
        if (*(char *)(puVar2 + 6) == '\0') {
          uVar9 = uStack124;
        }
        uStack116 = 0;
        do {
          iVar7 = (**(code **)(*piVar5 + 0xc4))
                            (piVar5,*puVar2,puVar2[1],puVar2[4],uStack116,uVar9 - uStack116);
          if (iVar7 < 1) {
            cVar4 = (**(code **)(*piVar5 + 0x390))(piVar5);
            uVar3 = extraout_ECX_01;
            if (cVar4 != '\0') {
              (**(code **)(*piVar5 + 0x44))(piVar5);
              uVar3 = extraout_ECX_02;
            }
            break;
          }
          uStack116 = uStack116 + iVar7;
          uVar3 = extraout_ECX_00;
        } while (uStack116 < uVar9);
        if ((int)uStack124 <= (int)uStack116) {
          uStack116 = uVar3 & 0xffffff00 | (uint)piStack68 & 0xff;
        }
        uStack124 = uStack116 & 0xff;
        (**(code **)(*piVar5 + 800))(piVar5,puVar2[4],0,uStack124,iStack72);
        if (*(char *)(puVar2 + 6) != '\0') goto LAB_00014622;
      }
      else {
        if ((int)(iVar7 + uStack124) < 0x2001) {
          (**(code **)(*piVar5 + 800))(piVar5,puVar2[4],iVar7,uStack124,iStack72);
LAB_00014622:
          uStack124 = uStack124 + puVar2[5];
        }
        else {
          iVar8 = 0x2000 - iVar7;
          (**(code **)(*piVar5 + 800))(piVar5,puVar2[4],iVar7,iVar8,iStack72);
          uVar9 = 0;
          do {
            iVar7 = (**(code **)(*piVar5 + 0xc4))
                              (piVar5,*puVar2,puVar2[1],puVar2[4],uVar9,0x2000 - uVar9);
            if (iVar7 < 1) {
              cVar4 = (**(code **)(*piVar5 + 0x390))(piVar5);
              if (cVar4 != '\0') {
                (**(code **)(*piVar5 + 0x44))(piVar5);
              }
              break;
            }
            uVar9 = uVar9 + iVar7;
          } while (uVar9 < 0x2000);
          uStack124 = uStack124 - iVar8;
          if ((int)uVar9 < (int)uStack124) {
            uStack116 = uVar9;
          }
          if ((int)uVar9 <= (int)uStack124) {
            uStack124 = uVar9;
          }
          (**(code **)(*piVar5 + 800))(piVar5,puVar2[4],0,uStack124,iStack72 + iVar8);
        }
        puVar2[5] = uStack124;
      }
      uVar10 = (**(code **)(*piVar5 + 0x368))(piVar5,*puVar2);
      uVar6 = (undefined4)((ulonglong)uVar10 >> 0x20);
      if ((int)uVar10 == 0) goto LAB_000146b3;
    }
  }
  uStack116 = 0;
LAB_000146b3:
  return CONCAT44(uVar6,uStack116);
}



uint FUN_00014440(int param_1,int param_2,byte param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  uint extraout_ECX;
  uint extraout_ECX_00;
  int iVar6;
  uint extraout_ECX_01;
  uint extraout_ECX_02;
  uint uVar7;
  uint uStack44;
  uint uStack36;
  
  puVar1 = *(undefined4 **)(param_1 + 0x34);
  piVar4 = (int *)FUN_00016080();
  if (piVar4 == (int *)0x0) {
    return 0;
  }
  iVar5 = (**(code **)(*piVar4 + 0x364))(piVar4,*puVar1);
  if (iVar5 != 0) {
    return 0;
  }
  uStack44 = (uint)param_3;
  uStack36 = extraout_ECX & 0xffffff00 | uStack44;
  iVar5 = puVar1[5];
  if (iVar5 == 0) {
    uVar7 = 0x2000;
    if (*(char *)(puVar1 + 6) == '\0') {
      uVar7 = uStack44;
    }
    uStack36 = 0;
    do {
      iVar5 = (**(code **)(*piVar4 + 0xc4))
                        (piVar4,*puVar1,puVar1[1],puVar1[4],uStack36,uVar7 - uStack36);
      if (iVar5 < 1) {
        cVar3 = (**(code **)(*piVar4 + 0x390))(piVar4);
        uVar2 = extraout_ECX_01;
        if (cVar3 != '\0') {
          (**(code **)(*piVar4 + 0x44))(piVar4);
          uVar2 = extraout_ECX_02;
        }
        break;
      }
      uStack36 = uStack36 + iVar5;
      uVar2 = extraout_ECX_00;
    } while (uStack36 < uVar7);
    if ((int)uStack44 <= (int)uStack36) {
      uStack36 = uVar2 & 0xffffff00 | (uint)param_3;
    }
    uStack44 = uStack36 & 0xff;
    (**(code **)(*piVar4 + 800))(piVar4,puVar1[4],0,uStack44,param_2);
    if (*(char *)(puVar1 + 6) == '\0') goto LAB_00014698;
LAB_00014622:
    uStack44 = uStack44 + puVar1[5];
  }
  else {
    if ((int)(iVar5 + uStack44) < 0x2001) {
      (**(code **)(*piVar4 + 800))(piVar4,puVar1[4],iVar5,uStack44,param_2);
      goto LAB_00014622;
    }
    iVar6 = 0x2000 - iVar5;
    (**(code **)(*piVar4 + 800))(piVar4,puVar1[4],iVar5,iVar6,param_2);
    uVar7 = 0;
    do {
      iVar5 = (**(code **)(*piVar4 + 0xc4))(piVar4,*puVar1,puVar1[1],puVar1[4],uVar7,0x2000 - uVar7)
      ;
      if (iVar5 < 1) {
        cVar3 = (**(code **)(*piVar4 + 0x390))(piVar4);
        if (cVar3 != '\0') {
          (**(code **)(*piVar4 + 0x44))(piVar4);
        }
        break;
      }
      uVar7 = uVar7 + iVar5;
    } while (uVar7 < 0x2000);
    uStack44 = uStack44 - iVar6;
    if ((int)uVar7 < (int)uStack44) {
      uStack36 = uVar7;
    }
    if ((int)uVar7 <= (int)uStack44) {
      uStack44 = uVar7;
    }
    (**(code **)(*piVar4 + 800))(piVar4,puVar1[4],0,uStack44,param_2 + iVar6);
  }
  puVar1[5] = uStack44;
LAB_00014698:
  iVar5 = (**(code **)(*piVar4 + 0x368))(piVar4,*puVar1);
  if (iVar5 != 0) {
    return 0;
  }
  return uStack36;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int Java_pl_droidsonroids_gif_GifInfoHandle_extractNativeFileDescriptor
              (int *param_1,undefined4 param_2,undefined4 param_3)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = -1;
  cVar1 = FUN_000138a0(param_3,param_1);
  if (cVar1 == '\0') {
    uVar2 = (**(code **)(*param_1 + 0x7c))(param_1,param_3);
    if ((_DAT_0001b010 == 0) &&
       (_DAT_0001b010 = (**(code **)(*param_1 + 0x178))(param_1,uVar2,&UNK_00017c64,&UNK_00017c6f),
       _DAT_0001b010 == 0)) {
      return -1;
    }
    uVar2 = (**(code **)(*param_1 + 400))(param_1,param_3,_DAT_0001b010);
    iVar3 = func_0x00011c30(uVar2);
    if (iVar3 == -1) {
      FUN_00013930(0x65,param_1,1);
    }
    func_0x00011c40(uVar2);
  }
  return iVar3;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_createTempNativeFileDescriptor(void)

{
  func_0x00011c50(0,0);
  return;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong Java_pl_droidsonroids_gif_GifInfoHandle_openNativeFileDescriptor
                    (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  longlong lVar5;
  ulonglong uVar6;
  undefined auStack160 [4];
  undefined auStack156 [8];
  undefined uStack148;
  code *pcStack144;
  uint uStack140;
  uint uStack136;
  undefined auStack120 [44];
  uint uStack76;
  uint uStack72;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  lVar5 = func_0x00011c60(param_3,param_4,param_5,0);
  if (lVar5 == -1) {
    FUN_00013930(0x65,param_1,1);
  }
  else {
    iVar1 = func_0x00011c70(param_3,&UNK_00017c05);
    if (iVar1 != 0) {
      iVar2 = func_0x00011c80(param_3,auStack120);
      uStack140 = uStack76 | ~-(uint)(iVar2 == 0);
      uStack136 = ~-(uint)(iVar2 == 0) | uStack72;
      _auStack160 = ZEXT816(0);
      pcStack144 = FUN_00013a50;
      uVar3 = FUN_00014960(iVar1,FUN_00014920,auStack156);
      _auStack160 = CONCAT124(_auStack156,uVar3);
      iVar1 = func_0x00011c10(iVar1);
      _auStack160 = CONCAT412(iVar1 >> 0x1f,CONCAT48(iVar1,_auStack160));
      uVar4 = FUN_00015d50(auStack160,param_1);
      if (uVar4 == 0) {
        func_0x00011c40(param_3);
      }
      goto LAB_00014904;
    }
    FUN_00013930(0x65,param_1,1);
  }
  func_0x00011c40(param_3);
  uVar4 = 0;
LAB_00014904:
  if (___stack_chk_guard == iStack24) {
    return (ulonglong)uVar4;
  }
  func_0x00011af0();
  uVar6 = func_0x00011c90(auStack156._4_4_,1,uStack148,*(undefined4 *)(auStack156._0_4_ + 0x34));
  return uVar6;
}



void FUN_00014920(int param_1,undefined4 param_2,undefined param_3)

{
  func_0x00011c90(param_2,1,param_3,*(undefined4 *)(param_1 + 0x34));
  return;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00014960(undefined4 param_1,code *param_2,undefined4 *param_3)

{
  undefined8 uVar1;
  uint **ppuVar2;
  undefined4 *puVar3;
  byte *pbVar4;
  char cVar5;
  byte bVar6;
  int iVar7;
  int iVar8;
  int **ppiVar9;
  int *piVar10;
  int **ppiVar11;
  int **ppiVar12;
  int **ppiVar13;
  undefined4 uVar14;
  uint uVar15;
  uint uVar16;
  int *piVar17;
  undefined (*pauVar18) [16];
  uint uVar19;
  undefined (*pauVar20) [16];
  int *piVar21;
  uint *puVar22;
  int *piVar23;
  int **ppiVar24;
  int **ppiVar25;
  ushort *puVar26;
  uint *puVar27;
  int **ppiVar28;
  bool bVar29;
  undefined auVar30 [16];
  undefined auVar31 [16];
  int *piVar32;
  int *piVar33;
  int *piVar34;
  undefined auVar35 [16];
  byte *pbStack444;
  byte *pbStack440;
  byte *pbStack436;
  byte bStack425;
  int *piStack424;
  undefined4 uStack420;
  int **ppiStack416;
  byte *pbStack412;
  undefined **ppuStack408;
  undefined *puStack404;
  int **ppiStack400;
  undefined4 uStack396;
  int *piStack392;
  int **ppiStack384;
  int *piStack380;
  undefined **ppuStack376;
  undefined *puStack372;
  int **ppiStack368;
  byte *pbStack364;
  uint *puStack360;
  int *piStack356;
  int **ppiStack352;
  byte bStack345;
  int *piStack344;
  int **ppiStack336;
  int **ppiStack332;
  undefined **ppuStack328;
  undefined *puStack324;
  int **ppiStack320;
  int **ppiStack316;
  int **ppiStack312;
  int **ppiStack304;
  int **ppiStack300;
  int **ppiStack296;
  int **ppiStack292;
  int **ppiStack288;
  int **ppiStack284;
  undefined **ppuStack280;
  int **ppiStack276;
  int **ppiStack272;
  int **ppiStack268;
  int **ppiStack264;
  int iStack260;
  int **ppiStack256;
  int **ppiStack252;
  int iStack248;
  int **ppiStack244;
  undefined auStack240 [16];
  int *piStack224;
  int *piStack220;
  int *piStack216;
  int *piStack212;
  byte bStack201;
  int *piStack200;
  undefined4 uStack196;
  uint uStack192;
  uint *puStack188;
  undefined **ppuStack184;
  undefined **appuStack180 [2];
  int **ppiStack172;
  int **ppiStack168;
  int **ppiStack164;
  byte bStack158;
  byte bStack157;
  undefined uStack156;
  undefined uStack155;
  ushort uStack154;
  int *piStack152;
  undefined4 uStack148;
  undefined *puStack144;
  int iStack140;
  undefined **ppuStack136;
  undefined *apuStack132 [2];
  undefined4 uStack124;
  int *piStack120;
  undefined4 uStack116;
  uint *puStack112;
  ushort *puStack108;
  undefined **ppuStack104;
  undefined *apuStack100 [2];
  int iStack92;
  undefined4 *puStack88;
  int **ppiStack84;
  byte bStack77;
  byte bStack76;
  undefined uStack75;
  ushort uStack74;
  int *piStack72;
  int iStack64;
  int **ppiStack60;
  undefined **ppuStack56;
  undefined *puStack52;
  undefined *puStack48;
  uint *puStack44;
  undefined4 uStack40;
  int **ppiStack36;
  uint uStack31;
  undefined uStack25;
  int *piStack24;
  
  ppuStack56 = &__DT_PLTGOT;
  piStack24 = ___stack_chk_guard;
  puStack44 = (uint *)0x3c;
  puStack48 = (undefined *)0x1;
  puStack52 = (undefined *)0x14998;
  iStack64 = func_0x00011ba0();
  if (iStack64 == 0) {
    iStack64 = 0;
    ppiStack60 = (int **)&__stack_chk_guard;
    if (param_3 != (undefined4 *)0x0) {
      *param_3 = 0x6d;
    }
  }
  else {
    puStack44 = (uint *)0x6130;
    puStack48 = (undefined *)0x1;
    puStack52 = (undefined *)0x149b6;
    ppiStack36 = (int **)&__stack_chk_guard;
    iVar7 = func_0x00011ba0();
    if (iVar7 == 0) {
      if (param_3 != (undefined4 *)0x0) {
        *param_3 = 0x6d;
      }
    }
    else {
      *(int *)(iStack64 + 0x38) = iVar7;
      *(code **)(iVar7 + 0x2c) = param_2;
      *(undefined4 *)(iStack64 + 0x34) = param_1;
      puStack44 = &uStack31;
      uStack40 = 6;
      puStack52 = (undefined *)0x149e0;
      puStack48 = (undefined *)iStack64;
      cVar5 = (*param_2)();
      if (cVar5 == '\x06') {
        uStack25 = 0;
        puStack44 = &uStack31;
        puStack48 = &UNK_00017c71;
        uStack40 = 3;
        puStack52 = (undefined *)0x14a07;
        iVar8 = func_0x00011b40();
        if (iVar8 == 0) {
          puStack52 = (undefined *)0x14a77;
          puStack48 = (undefined *)iStack64;
          iVar8 = FUN_00014ac0();
          if (iVar8 == 0) {
            puStack52 = (undefined *)0x14a95;
            puStack48 = (undefined *)iVar7;
            func_0x00011b80();
            puStack52 = (undefined *)0x14a9d;
            puStack48 = (undefined *)iStack64;
            func_0x00011b80();
            iStack64 = 0;
            ppiStack60 = ppiStack36;
            if (param_3 != (undefined4 *)0x0) {
              *param_3 = 0x68;
            }
          }
          else {
            *(undefined4 *)(iStack64 + 0x30) = 0;
            *param_3 = 0;
            ppiStack60 = ppiStack36;
          }
          goto LAB_00014a5d;
        }
        if (param_3 != (undefined4 *)0x0) {
          *param_3 = 0x67;
        }
      }
      else if (param_3 != (undefined4 *)0x0) {
        *param_3 = 0x66;
      }
      puStack52 = &LAB_00014a4f;
      puStack48 = (undefined *)iVar7;
      func_0x00011b80();
    }
    puStack52 = (undefined *)0x14a57;
    puStack48 = (undefined *)iStack64;
    func_0x00011b80();
    iStack64 = 0;
    ppiStack60 = ppiStack36;
  }
LAB_00014a5d:
  if (*ppiStack60 == piStack24) {
    return iStack64;
  }
  puStack52 = (undefined *)0x14ab3;
  func_0x00011af0();
  puVar27 = puStack44;
  apuStack100[0] = &LAB_00014ad1;
  ppiStack84 = (int **)&__stack_chk_guard;
  piStack72 = ___stack_chk_guard;
  puVar26 = &uStack74;
  ppuStack104 = (undefined **)0x2;
  puStack112 = puStack44;
  uStack116 = 0x14afc;
  puStack108 = puVar26;
  puStack52 = &stack0xfffffffc;
  cVar5 = (**(code **)(puStack44[0xe] + 0x2c))();
  if (cVar5 == '\x02') {
    *puVar27 = (uint)uStack74;
    ppuStack104 = (undefined **)0x2;
    puStack112 = puVar27;
    uStack116 = 0x14b25;
    puStack108 = puVar26;
    cVar5 = (**(code **)(puVar27[0xe] + 0x2c))();
    if (cVar5 != '\x02') goto LAB_00014c56;
    puVar27[1] = (uint)uStack74;
    puStack108 = (ushort *)&bStack77;
    ppuStack104 = (undefined **)0x3;
    puStack112 = puVar27;
    uStack116 = 0x14b53;
    cVar5 = (**(code **)(puVar27[0xe] + 0x2c))();
    if (cVar5 != '\x03') {
      puVar27[0xc] = 0x66;
      puStack112 = (uint *)puVar27[3];
      uStack116 = 0x14b8d;
      FUN_00015c20();
      puVar27[3] = 0;
      goto LAB_00014c5d;
    }
    puVar27[2] = (uint)bStack76;
    if ((char)bStack77 < '\0') {
      puStack112 = (uint *)(uint)(byte)((bStack77 & 7) + 1);
      puStack108 = (ushort *)0x0;
      uStack116 = 0x14bb6;
      piVar10 = (int *)FUN_00015b90();
      puVar27[3] = (uint)piVar10;
      if (piVar10 == (int *)0x0) {
        puVar27[0xc] = 0x6d;
        goto LAB_00014c5d;
      }
      iVar7 = 1;
      if (*piVar10 != 0) {
        puVar22 = (uint *)0x0;
        puVar26 = (ushort *)0x2;
        do {
          ppuStack104 = (undefined **)0x3;
          puStack108 = (ushort *)&bStack77;
          puStack112 = puStack44;
          uStack116 = 0x14bf6;
          cVar5 = (**(code **)(puStack44[0xe] + 0x2c))();
          puVar27 = puStack44;
          if (cVar5 != '\x03') {
            puStack112 = (uint *)puStack44[3];
            uStack116 = 0x14c4c;
            FUN_00015c20();
            puVar27[3] = 0;
            goto LAB_00014c56;
          }
          ppuVar2 = (uint **)puStack44[3];
          puVar27 = ppuVar2[2];
          *(byte *)(((int)puVar27 - 2U) + (int)puVar26) = bStack77;
          *(byte *)(((int)puVar27 - 1U) + (int)puVar26) = bStack76;
          *(undefined *)((int)puVar27 + (int)puVar26) = uStack75;
          puVar22 = (uint *)((int)puVar22 + 1);
          puVar26 = (ushort *)((int)puVar26 + 3);
        } while (puVar22 < *ppuVar2);
        iVar7 = 1;
        puVar27 = puVar22;
      }
    }
    else {
      puVar27[3] = 0;
      iVar7 = 1;
    }
  }
  else {
LAB_00014c56:
    puVar27[0xc] = 0x66;
LAB_00014c5d:
    iVar7 = 0;
  }
  if (*ppiStack84 == piStack72) {
    return iVar7;
  }
  apuStack100[0] = (undefined *)0x14c7a;
  func_0x00011af0();
  apuStack132[0] = &LAB_00014c91;
  piStack120 = ___stack_chk_guard;
  iStack140 = (int)&uStack124 + 3;
  ppuStack136 = (undefined **)0x1;
  puStack144 = (undefined *)iStack92;
  uStack148 = 0x14cb8;
  puStack112 = puVar27;
  puStack108 = puVar26;
  ppuStack104 = &__DT_PLTGOT;
  apuStack100[0] = (undefined *)&puStack52;
  cVar5 = (**(code **)(*(int *)(iStack92 + 0x38) + 0x2c))();
  if (cVar5 == '\x01') {
    if (uStack124._3_1_ == '!') {
      uVar14 = 3;
    }
    else if (uStack124._3_1_ == ';') {
      uVar14 = 4;
    }
    else {
      if (uStack124._3_1_ != ',') {
        *puStack88 = 0;
        *(undefined4 *)(iStack92 + 0x30) = 0x6b;
        goto LAB_00014ce3;
      }
      uVar14 = 2;
    }
    *puStack88 = uVar14;
    iVar7 = 1;
  }
  else {
    *(undefined4 *)(iStack92 + 0x30) = 0x66;
LAB_00014ce3:
    iVar7 = 0;
  }
  if (___stack_chk_guard == piStack120) {
    return iVar7;
  }
  apuStack132[0] = (undefined *)0x14d1e;
  func_0x00011af0();
  iStack140 = iStack92;
  appuStack180[0] = (undefined **)&LAB_00014d31;
  ppiStack172 = (int **)&__stack_chk_guard;
  piStack152 = ___stack_chk_guard;
  ppiStack164 = *(int ***)(uStack124 + 0x38);
  puVar27 = (uint *)&uStack154;
  ppuStack184 = (undefined **)0x2;
  uStack192 = uStack124;
  uStack196 = 0x14d60;
  puStack188 = puVar27;
  puStack144 = &__stack_chk_guard;
  ppuStack136 = &__DT_PLTGOT;
  apuStack132[0] = (undefined *)apuStack100;
  cVar5 = (*(code *)ppiStack164[0xb])();
  if (cVar5 == '\x02') {
    *(uint *)(uStack124 + 0x14) = (uint)uStack154;
    ppuStack184 = (undefined **)0x2;
    uStack192 = uStack124;
    uStack196 = 0x14d8a;
    puStack188 = puVar27;
    cVar5 = (**(code **)(*(int *)(uStack124 + 0x38) + 0x2c))();
    if (cVar5 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack124 + 0x18) = (uint)uStack154;
    ppuStack184 = (undefined **)0x2;
    uStack192 = uStack124;
    uStack196 = 0x14db4;
    puStack188 = puVar27;
    cVar5 = (**(code **)(*(int *)(uStack124 + 0x38) + 0x2c))();
    if (cVar5 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack124 + 0x1c) = (uint)uStack154;
    ppuStack184 = (undefined **)0x2;
    uStack192 = uStack124;
    uStack196 = 0x14dde;
    puStack188 = puVar27;
    cVar5 = (**(code **)(*(int *)(uStack124 + 0x38) + 0x2c))();
    if (cVar5 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack124 + 0x20) = (uint)uStack154;
    puStack188 = (uint *)&bStack157;
    ppuStack184 = (undefined **)0x1;
    uStack192 = uStack124;
    uStack196 = 0x14e0c;
    cVar5 = (**(code **)(*(int *)(uStack124 + 0x38) + 0x2c))();
    if (cVar5 != '\x01') {
      *(undefined4 *)(uStack124 + 0x30) = 0x66;
      uStack192 = *(uint *)(uStack124 + 0x28);
      uStack196 = 0x14f38;
      FUN_00015c20();
LAB_00014f3b:
      *(undefined4 *)(uStack124 + 0x28) = 0;
      goto LAB_00014f0c;
    }
    *(byte *)(uStack124 + 0x24) = bStack157 >> 6 & 1;
    uStack192 = *(int *)(uStack124 + 0x28);
    ppiStack168._0_1_ = bStack157;
    if (uStack192 != 0) {
      ppiStack168 = (int **)((uint)ppiStack168 & 0xffffff00 | (uint)bStack157);
      uStack196 = 0x14e3b;
      FUN_00015c20();
      *(undefined4 *)(uStack124 + 0x28) = 0;
    }
    if ((char)bStack157 < '\0') {
      uStack192 = (uint)(byte)(((byte)ppiStack168 & 7) + 1);
      puStack188 = (uint *)0x0;
      uStack196 = 0x14f5f;
      piVar10 = (int *)FUN_00015b90();
      *(int **)(uStack124 + 0x28) = piVar10;
      if (piVar10 != (int *)0x0) {
        if (*piVar10 != 0) {
          ppiVar9 = (int **)0x0;
          puVar27 = (uint *)0x2;
          do {
            ppuStack184 = (undefined **)0x3;
            puStack188 = (uint *)&bStack157;
            uStack192 = uStack124;
            uStack196 = 0x14f8e;
            ppiStack168 = ppiVar9;
            cVar5 = (**(code **)(*(int *)(uStack124 + 0x38) + 0x2c))();
            if (cVar5 != '\x03') {
              uStack192 = *(uint *)(uStack124 + 0x28);
              uStack196 = 0x15055;
              FUN_00015c20();
              *(undefined4 *)(uStack124 + 0x30) = 0x66;
              goto LAB_00014f3b;
            }
            puVar3 = *(undefined4 **)(uStack124 + 0x28);
            iVar7 = puVar3[2];
            *(byte *)(iVar7 + -2 + (int)puVar27) = bStack157;
            *(undefined *)(iVar7 + -1 + (int)puVar27) = uStack156;
            *(undefined *)(iVar7 + (int)puVar27) = uStack155;
            ppiVar9 = (int **)((int)ppiStack168 + 1);
            puVar27 = (uint *)((int)puVar27 + 3);
          } while (ppiVar9 < (int **)*puVar3);
        }
        goto LAB_00014e55;
      }
LAB_00014fca:
      *(undefined4 *)(uStack124 + 0x30) = 0x6d;
      goto LAB_00014f0c;
    }
LAB_00014e55:
    if ((char)piStack120 != '\0') {
      puStack188 = (uint *)(*(int *)(uStack124 + 0x10) + 1);
      ppuStack184 = (undefined **)0x18;
      uStack192 = *(uint *)(uStack124 + 0x2c);
      uStack196 = 0x14e6e;
      ppiVar9 = (int **)FUN_00015cf0();
      if (ppiVar9 == (int **)0x0) goto LAB_00014fca;
      *(int ***)(uStack124 + 0x2c) = ppiVar9;
      iVar7 = *(int *)(uStack124 + 0x10);
      puVar27 = (uint *)(iVar7 * 3);
      *(undefined8 *)(ppiVar9 + iVar7 * 6 + 4) = *(undefined8 *)(uStack124 + 0x24);
      uVar1 = *(undefined8 *)(uStack124 + 0x14);
      *(undefined8 *)(ppiVar9 + iVar7 * 6 + 2) = *(undefined8 *)(uStack124 + 0x1c);
      *(undefined8 *)(ppiVar9 + iVar7 * 6) = uVar1;
      iVar8 = *(int *)(uStack124 + 0x28);
      if (iVar8 != 0) {
        uStack192 = (uint)*(byte *)(iVar8 + 4);
        puStack188 = *(uint **)(iVar8 + 8);
        uStack196 = 0x14ebf;
        ppiStack168 = ppiVar9;
        piVar10 = (int *)FUN_00015b90();
        ppiStack168[iVar7 * 6 + 5] = piVar10;
        if (piVar10 == (int *)0x0) goto LAB_00014fca;
      }
      *(int *)(uStack124 + 0x10) = *(int *)(uStack124 + 0x10) + 1;
    }
    ppiStack164[10] = (int *)(*(int *)(uStack124 + 0x20) * *(int *)(uStack124 + 0x1c));
    puVar27 = *(uint **)(uStack124 + 0x38);
    puStack188 = (uint *)&bStack158;
    ppuStack184 = (undefined **)0x1;
    uStack192 = uStack124;
    uStack196 = 0x14ef4;
    (*(code *)puVar27[0xb])();
    uVar15 = (uint)bStack158;
    if (8 < uVar15) goto LAB_00014f05;
    *(undefined *)(puVar27 + 0xc) = 0;
    *puVar27 = uVar15;
    uVar16 = 1 << (bStack158 & 0x1f);
    puVar27[1] = uVar16;
    puVar27[2] = uVar16 + 1;
    iVar7 = 1;
    puVar27[3] = uVar16 + 2;
    puVar27[4] = uVar15 + 1;
    puVar27[5] = 2 << (bStack158 & 0x1f);
    *(undefined (*) [16])(puVar27 + 6) = ZEXT416(0x1002);
    iVar8 = -0x1000;
    do {
      puVar22 = puVar27 + iVar8 + 0x184c;
      *puVar22 = 0x1002;
      puVar22[1] = 0x1002;
      puVar22[2] = 0x1002;
      puVar22[3] = 0x1002;
      puVar22 = puVar27 + iVar8 + 0x1850;
      *puVar22 = 0x1002;
      puVar22[1] = 0x1002;
      puVar22[2] = 0x1002;
      puVar22[3] = 0x1002;
      iVar8 = iVar8 + 8;
    } while (iVar8 != 0);
  }
  else {
LAB_00014f05:
    *(undefined4 *)(uStack124 + 0x30) = 0x66;
LAB_00014f0c:
    iVar7 = 0;
  }
  if (*ppiStack172 == piStack152) {
    return iVar7;
  }
  appuStack180[0] = (undefined **)0x15069;
  func_0x00011af0();
  uStack192 = uStack124;
  ppuStack280 = &__DT_PLTGOT;
  piStack200 = ___stack_chk_guard;
  ppiStack332 = (int **)ppiStack172[0xe];
  ppiStack300 = ppiStack164;
  if (ppiStack164 == (int **)0x0) {
    ppiStack300 = (int **)ppiStack172[7];
  }
  piVar10 = ppiStack332[10];
  ppiStack332[10] = (int *)((int)piVar10 - (int)ppiStack300);
  auVar35 = _UNK_00017f30;
  ppiStack336 = ppiStack300;
  ppiVar9 = (int **)&__stack_chk_guard;
  puStack188 = puVar27;
  ppuStack184 = &__DT_PLTGOT;
  if ((int *)((int)piVar10 - (int)ppiStack300) < (int *)0xffff0001) {
    ppiVar28 = (int **)ppiStack332[7];
    iVar7 = 0;
    appuStack180[0] = apuStack132;
    if ((int)ppiVar28 < 0x1000) {
      ppiStack268 = (int **)ppiStack332[1];
      ppiStack244 = (int **)ppiStack332[2];
      ppiVar12 = (int **)ppiStack332[6];
      if (ppiVar28 == (int **)0x0) {
        ppiVar9 = (int **)0x0;
        ppiStack292 = (int **)0x0;
      }
      else if (ppiStack300 == (int **)0x0) {
        ppiVar9 = (int **)0x0;
        ppiStack292 = ppiVar28;
      }
      else {
        uVar19 = -(int)ppiStack300;
        uVar16 = -(int)ppiVar28;
        uVar15 = uVar16;
        if (uVar16 <= uVar19 && ppiVar28 != ppiStack300) {
          uVar15 = uVar19;
        }
        ppiVar11 = (int **)-uVar15;
        ppiVar9 = (int **)0x0;
        if ((int **)0x1f < ppiVar11) {
          if (uVar16 <= uVar19 && ppiVar28 != ppiStack300) {
            uVar16 = uVar19;
          }
          if (((int **)((int)(ppiStack332 + 0x4c) + (int)ppiVar28) <= ppiStack168) ||
             ((int)ppiStack168 - uVar16 <= (int)ppiStack332 + (int)ppiVar28 + uVar16 + 0x130)) {
            ppiVar9 = (int **)((uint)ppiVar11 & 0xffffffe0);
            pauVar18 = (undefined (*) [16])(ppiStack168 + 4);
            pauVar20 = (undefined (*) [16])((int)(ppiStack332 + 0x48) + (int)ppiVar28);
            ppiVar28 = (int **)((int)ppiVar28 - (int)ppiVar9);
            ppiStack336 = ppiVar9;
            do {
              auVar31 = pshufb(*pauVar20,auVar35);
              auVar30 = pshufb(pauVar20[-1],auVar35);
              pauVar18[-1] = auVar31;
              *pauVar18 = auVar30;
              pauVar18 = pauVar18[2];
              pauVar20 = pauVar20[-2];
              ppiStack336 = ppiStack336 + -8;
            } while (ppiStack336 != (int **)0x0);
            ppiStack292 = ppiVar28;
            ppiStack304 = ppiStack332;
            if (ppiVar9 == ppiVar11) goto LAB_00015209;
          }
        }
        do {
          *(undefined *)((int)ppiStack168 + (int)ppiVar9) =
               *(undefined *)((int)ppiStack332 + 0x12f + (int)ppiVar28);
          ppiStack292 = (int **)((int)ppiVar28 + -1);
          ppiVar9 = (int **)((int)ppiVar9 + 1);
          ppiStack336 = ppiStack168;
          ppiStack304 = ppiStack332;
          if (ppiStack300 <= ppiVar9) break;
          bVar29 = ppiVar28 != (int **)0x1;
          ppiVar28 = ppiStack292;
        } while (bVar29);
      }
LAB_00015209:
      ppiStack288 = (int **)&__stack_chk_guard;
      appuStack180[0] = apuStack132;
      if (ppiVar9 < ppiStack300) {
        iStack260 = (int)ppiStack332 + 0x131;
        ppiStack252 = ppiStack168 + 4;
        iStack248 = (int)ppiStack332 + 0x121;
        piVar10 = (int *)0x1002;
        piVar32 = (int *)0x1002;
        piVar33 = (int *)0x1002;
        piVar34 = (int *)0x1002;
        auStack240 = _UNK_00017f30;
        auVar35 = _UNK_00017f30;
        ppiStack304 = ppiStack332;
        ppiStack276 = ppiVar12;
        piStack224 = piVar10;
        piStack220 = piVar32;
        piStack216 = piVar33;
        piStack212 = piVar34;
        appuStack180[0] = apuStack132;
        do {
          ppiStack332 = (int **)ppiStack172[0xe];
          piVar21 = ppiStack332[4];
          if ((int *)0xc < piVar21) {
            ppiStack172[0xc] = (int *)0x70;
            ppiStack336 = ppiStack172;
            goto LAB_00015824;
          }
          piVar17 = ppiStack332[8];
          ppiStack296 = ppiVar9;
          if (piVar17 < piVar21) {
            ppiStack284 = ppiStack332 + 0xc;
            ppiStack272 = (int **)((int)ppiStack332 + 0x31);
            cVar5 = *(char *)(ppiStack332 + 0xc);
            do {
              ppiStack336 = ppiStack284;
              if (cVar5 == '\0') {
                ppiStack316 = ppiStack284;
                ppiStack320 = ppiStack172;
                ppiStack312 = (int **)0x1;
                puStack324 = (undefined *)0x152d2;
                cVar5 = (*(code *)ppiStack172[0xe][0xb])();
                ppiVar9 = ppiStack172;
                if (cVar5 != '\x01') {
                  ppiStack172[0xc] = (int *)0x66;
                  goto LAB_00015824;
                }
                if (*(byte *)ppiStack336 == 0) goto LAB_000157e6;
                ppiStack312 = (int **)(uint)*(byte *)ppiStack336;
                ppiStack316 = ppiStack272;
                ppiStack320 = ppiStack172;
                puStack324 = (undefined *)0x15300;
                uVar15 = (*(code *)ppiStack172[0xe][0xb])();
                if ((char)uVar15 != *(char *)ppiStack284) goto LAB_000157dd;
                bVar6 = *(byte *)((int)ppiStack332 + 0x31);
                *(undefined *)((int)ppiStack332 + 0x31) = 2;
                piVar21 = ppiStack332[4];
                piVar17 = ppiStack332[8];
                auVar35 = auStack240;
                piVar10 = piStack224;
                piVar32 = piStack220;
                piVar33 = piStack216;
                piVar34 = piStack212;
              }
              else {
                bVar6 = *(byte *)((int)ppiStack332 + 0x31);
                uVar15 = (uint)CONCAT11(bVar6 + 1,cVar5);
                *(char *)((int)ppiStack332 + 0x31) = (char)(uVar15 >> 8);
                bVar6 = *(byte *)((int)ppiStack332 + bVar6 + 0x30);
              }
              cVar5 = (char)uVar15 + -1;
              *(char *)(ppiStack332 + 0xc) = cVar5;
              piVar23 = (int *)((uint)bVar6 << ((byte)piVar17 & 0x1f) | (uint)ppiStack332[9]);
              ppiStack332[9] = piVar23;
              piVar17 = piVar17 + 2;
              ppiStack332[8] = piVar17;
            } while (piVar17 < piVar21);
          }
          else {
            piVar23 = ppiStack332[9];
          }
          ppiVar12 = (int **)((uint)*(ushort *)((int)ppuStack280 + (int)piVar21 * 2 + -0x2fe4) &
                             (uint)piVar23);
          ppiStack332[9] = (int *)((uint)piVar23 >> ((byte)piVar21 & 0x1f));
          ppiStack332[8] = (int *)((int)piVar17 - (int)piVar21);
          if (ppiStack332[3] < (int *)0x1001) {
            piVar17 = (int *)((int)ppiStack332[3] + 1);
            ppiStack332[3] = piVar17;
            if ((piVar21 < (int *)0xc) && (ppiStack332[5] < piVar17)) {
              ppiStack332[5] = (int *)((int)ppiStack332[5] * 2);
              ppiStack332[4] = (int *)((int)piVar21 + 1);
            }
          }
          ppiStack336 = ppiStack172;
          if (ppiVar12 == ppiStack244) {
            ppiStack172[0xc] = (int *)0x71;
            goto LAB_00015824;
          }
          if (ppiVar12 == ppiStack268) {
            iVar7 = -0x1000;
            do {
              ppiVar9 = ppiStack304 + iVar7 + 0x184c;
              *ppiVar9 = piVar10;
              ppiVar9[1] = piVar32;
              ppiVar9[2] = piVar33;
              ppiVar9[3] = piVar34;
              ppiVar9 = ppiStack304 + iVar7 + 0x1850;
              *ppiVar9 = piVar10;
              ppiVar9[1] = piVar32;
              ppiVar9[2] = piVar33;
              ppiVar9[3] = piVar34;
              iVar7 = iVar7 + 8;
            } while (iVar7 != 0);
            ppiStack304[3] = (int *)((int)ppiStack304[2] + 1);
            ppiStack304[4] = (int *)((int)*ppiStack304 + 1);
            ppiStack304[5] = (int *)(1 << ((byte)(int *)((int)*ppiStack304 + 1) & 0x1f));
            ppiStack304[6] = (int *)0x1002;
            ppiVar12 = (int **)0x1002;
          }
          else {
            ppiStack284 = ppiVar12;
            if ((int)ppiStack268 <= (int)ppiVar12) {
              ppiVar9 = ppiVar12;
              ppiVar28 = ppiStack292;
              if (ppiStack304[(int)(ppiVar12 + 0x213)] == (int *)0x1002) {
                if (ppiVar12 != (int **)((int)ppiStack304[3] + -2)) {
                  ppiStack172[0xc] = (int *)0x70;
                  ppiVar9 = ppiStack288;
                  goto LAB_000150c5;
                }
                ppiVar9 = ppiStack276;
                if ((int)ppiStack268 < (int)ppiStack276) {
                  iVar7 = 1;
                  while ((int)ppiVar9 < 0x1000) {
                    ppiVar9 = (int **)ppiStack304[(int)(ppiVar9 + 0x213)];
                    if ((0xfff < iVar7) ||
                       (iVar7 = iVar7 + (uint)((int)ppiStack268 < (int)ppiVar9),
                       (int)ppiVar9 <= (int)ppiStack268)) goto LAB_0001556c;
                  }
                  ppiVar9 = (int **)0x1002;
                }
LAB_0001556c:
                *(char *)((int)(ppiStack304 + 0x4c) + (int)ppiStack292) = (char)ppiVar9;
                *(char *)((int)ppiStack304 + 0x112d + (int)ppiStack304[3]) = (char)ppiVar9;
                ppiStack332 = ppiStack276;
                ppiVar9 = ppiStack276;
                ppiVar28 = (int **)((int)ppiStack292 + 1);
                ppiStack336 = ppiStack304;
              }
              if ((int)ppiVar28 < 0xfff) {
                pauVar18 = (undefined (*) [16])(iStack248 + (int)ppiVar28);
                ppiStack332 = (int **)~(uint)ppiVar28;
                while (((int)ppiStack268 < (int)ppiVar9 && ((int)ppiVar9 < 0x1000))) {
                  *(undefined *)((int)(ppiStack304 + 0x4c) + (int)ppiVar28) =
                       *(undefined *)((int)ppiStack304 + 0x112f + (int)ppiVar9);
                  ppiVar9 = (int **)ppiStack304[(int)(ppiVar9 + 0x213)];
                  pauVar18 = (undefined (*) [16])(*pauVar18 + 1);
                  ppiStack332 = (int **)((int)ppiStack332 + -1);
                  bVar29 = 0xffd < (int)ppiVar28;
                  ppiVar28 = (int **)((int)ppiVar28 + 1);
                  ppiStack336 = ppiStack304;
                  if (bVar29) goto LAB_000157e6;
                }
                if ((int)ppiVar9 < 0x1000) {
                  ppiVar11 = (int **)((int)ppiVar28 + 1);
                  *(char *)((int)(ppiStack304 + 0x4c) + (int)ppiVar28) = (char)ppiVar9;
                  ppiVar9 = (int **)((int)ppiStack296 - (int)ppiStack300);
                  ppiStack292 = ppiVar11;
                  if ((ppiStack296 < ppiStack300) && (ppiVar11 != (int **)0x0)) {
                    ppiVar24 = (int **)~(uint)ppiVar28;
                    ppiVar13 = ppiVar24;
                    if (ppiVar24 < ppiVar9) {
                      ppiVar13 = ppiVar9;
                    }
                    ppiVar13 = (int **)-(int)ppiVar13;
                    if ((int **)0x1f < ppiVar13) {
                      ppiStack272 = (int **)((int)ppiStack168 + (int)ppiStack296);
                      ppiVar25 = ppiVar24;
                      if (ppiVar24 < ppiVar9) {
                        ppiVar25 = ppiVar9;
                      }
                      ppiStack264 = ppiVar13;
                      ppiStack256 = ppiVar24;
                      if (((int **)(iStack260 + (int)ppiVar28) <= ppiStack272) ||
                         ((uint)(((int)ppiStack296 - (int)ppiVar25) + (int)ppiStack168) <=
                          (uint)((int)ppiVar28 + (int)ppiVar25 + iStack260))) {
                        ppiStack272 = (int **)((uint)ppiVar13 & 0xffffffe0);
                        ppiVar11 = (int **)((int)ppiVar11 - (int)ppiStack272);
                        pauVar20 = (undefined (*) [16])((int)ppiStack252 + (int)ppiStack296);
                        ppiStack296 = (int **)((int)ppiStack296 + (int)ppiStack272);
                        if (ppiVar9 < ppiStack332) {
                          ppiVar9 = ppiStack332;
                        }
                        uVar15 = -(int)ppiVar9 & 0xffffffe0;
                        do {
                          auVar31 = pshufb(*pauVar18,auVar35);
                          auVar30 = pshufb(pauVar18[-1],auVar35);
                          pauVar20[-1] = auVar31;
                          *pauVar20 = auVar30;
                          pauVar20 = pauVar20[2];
                          pauVar18 = pauVar18[-2];
                          uVar15 = uVar15 - 0x20;
                        } while (uVar15 != 0);
                        ppiStack292 = ppiVar11;
                        if (ppiStack272 == ppiVar13) goto LAB_00015416;
                      }
                    }
                    do {
                      *(undefined *)((int)ppiStack168 + (int)ppiStack296) =
                           *(undefined *)((int)ppiStack304 + 0x12f + (int)ppiVar11);
                      ppiStack292 = (int **)((int)ppiVar11 + -1);
                      ppiStack296 = (int **)((int)ppiStack296 + 1);
                      if (ppiStack300 <= ppiStack296) break;
                      bVar29 = ppiVar11 != (int **)0x1;
                      ppiVar11 = ppiStack292;
                    } while (bVar29);
                  }
                  goto LAB_00015416;
                }
              }
LAB_000157e6:
              ppiStack172[0xc] = (int *)0x70;
              goto LAB_00015824;
            }
            *(char *)((int)ppiStack168 + (int)ppiStack296) = (char)ppiVar12;
            ppiStack296 = (int **)((int)ppiStack296 + 1);
LAB_00015416:
            if ((ppiStack276 != (int **)0x1002) &&
               (ppiStack304[(int)ppiStack304[3] + 0x84a] == (int *)0x1002)) {
              ppiStack304[(int)ppiStack304[3] + 0x84a] = (int *)ppiStack276;
              if (ppiVar12 != (int **)((int)ppiStack304[3] + -2)) {
                ppiStack276 = ppiVar12;
              }
              if ((int)ppiStack268 < (int)ppiStack276) {
                iVar7 = 1;
                while ((int)ppiStack276 < 0x1000) {
                  ppiStack276 = (int **)ppiStack304[(int)(ppiStack276 + 0x213)];
                  if ((0xfff < iVar7) ||
                     (iVar7 = iVar7 + (uint)((int)ppiStack268 < (int)ppiStack276),
                     (int)ppiStack276 <= (int)ppiStack268)) goto LAB_0001572a;
                }
                ppiStack276 = (int **)0x1002;
              }
LAB_0001572a:
              *(char *)((int)ppiStack304 + 0x112f + (int)(int **)((int)ppiStack304[3] + -2)) =
                   (char)ppiStack276;
            }
          }
          ppiVar9 = ppiStack296;
          ppiStack336 = ppiStack172;
          ppiStack332 = ppiStack304;
          ppiStack276 = ppiVar12;
        } while (ppiStack296 < ppiStack300);
      }
      ppiStack332[6] = (int *)ppiVar12;
      ppiStack332[7] = (int *)ppiStack292;
      iVar7 = 1;
      ppiVar9 = ppiStack288;
      ppiStack276 = ppiVar12;
      if (ppiStack332[10] == (int *)0x0) {
        ppiStack332 = (int **)ppiStack172[0xe];
        ppiStack336 = ppiStack172;
        while( true ) {
          ppiStack316 = (int **)&bStack201;
          ppiStack312 = (int **)0x1;
          puStack324 = (undefined *)0x157a9;
          ppiStack320 = ppiStack336;
          cVar5 = (*(code *)ppiStack332[0xb])();
          ppiVar28 = ppiStack172;
          ppiVar9 = ppiStack336;
          if (cVar5 != '\x01') break;
          if (bStack201 == 0) {
            *(undefined *)(ppiStack332 + 0xc) = 0;
            ppiStack332[10] = (int *)0x0;
            iVar7 = 1;
            ppiVar9 = ppiStack288;
            goto LAB_0001582a;
          }
          *(byte *)(ppiStack332 + 0xc) = bStack201;
          ppiStack332 = (int **)((int)ppiStack332 + 0x31);
          ppiStack312 = (int **)(uint)bStack201;
          ppiStack320 = ppiStack172;
          puStack324 = (undefined *)0x157d7;
          ppiStack316 = ppiStack332;
          bVar6 = (*(code *)ppiStack172[0xe][0xb])();
          ppiVar9 = ppiVar28;
          if (bVar6 != bStack201) break;
          ppiStack332 = (int **)ppiVar28[0xe];
          ppiStack336 = ppiVar28;
        }
LAB_000157dd:
        ppiVar9[0xc] = (int *)0x66;
        ppiStack336 = ppiVar9;
LAB_00015824:
        iVar7 = 0;
        ppiVar9 = ppiStack288;
      }
    }
  }
  else {
    ppiStack172[0xc] = (int *)0x6c;
    appuStack180[0] = apuStack132;
LAB_000150c5:
    iVar7 = 0;
  }
LAB_0001582a:
  ppuStack328 = ppuStack280;
  if (*ppiVar9 == piStack200) {
    return iVar7;
  }
  puStack324 = (undefined *)0x15852;
  func_0x00011af0();
  ppiStack384 = ppiStack316;
  ppuStack376 = &__DT_PLTGOT;
  ppiStack352 = (int **)&__stack_chk_guard;
  piStack344 = ___stack_chk_guard;
  piStack380 = ppiStack316[0xe];
  pbStack364 = &bStack345;
  ppiStack368 = ppiStack316;
  puStack360 = (uint *)0x1;
  puStack372 = (undefined *)0x158a4;
  puStack324 = (undefined *)appuStack180;
  cVar5 = (*(code *)piStack380[0xb])();
  if (cVar5 == '\x01') {
    if (bStack345 == 0) {
      *ppiStack312 = (int *)0x0;
      *(undefined *)(piStack380 + 0xc) = 0;
      piStack380[10] = 0;
      iVar7 = 1;
    }
    else {
      *ppiStack312 = piStack380 + 0xc;
      *(byte *)(piStack380 + 0xc) = bStack345;
      pbStack364 = (byte *)((int)*ppiStack312 + 1);
      puStack360 = (uint *)(uint)bStack345;
      ppiStack368 = ppiStack384;
      puStack372 = (undefined *)0x158d2;
      bVar6 = (*(code *)ppiStack384[0xe][0xb])();
      iVar7 = 1;
      if (bVar6 != bStack345) goto LAB_000158df;
    }
  }
  else {
LAB_000158df:
    ppiStack384[0xc] = (int *)0x66;
    iVar7 = 0;
  }
  if (*ppiStack352 == piStack344) {
    return iVar7;
  }
  puStack372 = (undefined *)0x15919;
  func_0x00011af0();
  pbVar4 = pbStack364;
  puStack404 = &LAB_00015931;
  piStack392 = ___stack_chk_guard;
  pbStack412 = (byte *)((int)&uStack396 + 2);
  ppuStack408 = (undefined **)0x1;
  ppiStack416 = (int **)pbStack364;
  uStack420 = 0x15958;
  puStack372 = (undefined *)&puStack324;
  cVar5 = (**(code **)(*(int *)(pbStack364 + 0x38) + 0x2c))();
  ppiVar9 = (int **)&__stack_chk_guard;
  if (cVar5 == '\x01') {
    *puStack360 = uStack396 >> 0x10 & 0xff;
    iVar7 = *(int *)(pbVar4 + 0x38);
    pbStack412 = (byte *)((int)&uStack396 + 3);
    ppuStack408 = (undefined **)0x1;
    ppiStack416 = (int **)pbVar4;
    uStack420 = 0x1597d;
    ppiStack400 = (int **)&__stack_chk_guard;
    cVar5 = (**(code **)(iVar7 + 0x2c))();
    ppiVar9 = ppiStack400;
    if (cVar5 == '\x01') {
      if (uStack396._3_1_ == 0) {
        *piStack356 = 0;
        iVar7 = 1;
      }
      else {
        *piStack356 = iVar7 + 0x30;
        *(byte *)(iVar7 + 0x30) = uStack396._3_1_;
        pbStack412 = (byte *)(*piStack356 + 1);
        ppuStack408 = (undefined **)(uint)uStack396._3_1_;
        ppiStack416 = (int **)pbVar4;
        uStack420 = 0x159b1;
        cVar5 = (**(code **)(*(int *)(pbVar4 + 0x38) + 0x2c))();
        iVar7 = 1;
        ppiVar9 = ppiStack400;
        if (cVar5 != uStack396._3_1_) goto LAB_000159c4;
      }
    }
    else {
      *(undefined4 *)(pbVar4 + 0x30) = 0x66;
      iVar7 = 0;
    }
  }
  else {
LAB_000159c4:
    *(undefined4 *)(pbVar4 + 0x30) = 0x66;
    iVar7 = 0;
  }
  if (*ppiVar9 == piStack392) {
    return iVar7;
  }
  puStack404 = (undefined *)0x159fd;
  func_0x00011af0();
  pbStack412 = pbVar4;
  piStack424 = ___stack_chk_guard;
  iVar7 = *(int *)(uStack396 + 0x38);
  pbStack444 = &bStack425;
  pbStack440 = (byte *)0x1;
  ppiStack416 = ppiVar9;
  ppuStack408 = &__DT_PLTGOT;
  puStack404 = (undefined *)&puStack372;
  cVar5 = (**(code **)(iVar7 + 0x2c))(uStack396);
  if (cVar5 == '\x01') {
    if (bStack425 == 0) {
      *piStack392 = 0;
      iVar7 = 1;
      goto LAB_00015a95;
    }
    *piStack392 = iVar7 + 0x30;
    *(byte *)(iVar7 + 0x30) = bStack425;
    pbStack444 = (byte *)(*piStack392 + 1);
    pbStack440 = (byte *)(uint)bStack425;
    bVar6 = (**(code **)(*(int *)(uStack396 + 0x38) + 0x2c))(uStack396);
    iVar7 = 1;
    if (bVar6 == bStack425) goto LAB_00015a95;
  }
  *(undefined4 *)(uStack396 + 0x30) = 0x66;
  iVar7 = 0;
LAB_00015a95:
  if (___stack_chk_guard != piStack424) {
    func_0x00011af0();
    iVar7 = 0;
    if (pbStack444 == (byte *)0x4) {
      *pbStack436 = *pbStack440 >> 2 & 7;
      *(uint *)(pbStack436 + 4) = (uint)*(ushort *)(pbStack440 + 1);
      uVar15 = 0xffffffff;
      if ((*pbStack440 & 1) != 0) {
        uVar15 = (uint)pbStack440[3];
      }
      *(uint *)(pbStack436 + 8) = uVar15;
      iVar7 = 1;
    }
    return iVar7;
  }
  return iVar7;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00014ac0(uint *param_1)

{
  undefined8 uVar1;
  uint **ppuVar2;
  uint *puVar3;
  int iVar4;
  undefined4 *puVar5;
  byte *pbVar6;
  char cVar7;
  byte bVar8;
  int **ppiVar9;
  int *piVar10;
  int **ppiVar11;
  int **ppiVar12;
  int iVar13;
  int **ppiVar14;
  undefined4 uVar15;
  uint uVar16;
  uint uVar17;
  int *piVar18;
  undefined (*pauVar19) [16];
  uint uVar20;
  undefined (*pauVar21) [16];
  int *piVar22;
  int *piVar23;
  int **ppiVar24;
  int **ppiVar25;
  ushort *puVar26;
  uint *puVar27;
  int **ppiVar28;
  bool bVar29;
  undefined auVar30 [16];
  undefined auVar31 [16];
  int *piVar32;
  int *piVar33;
  int *piVar34;
  undefined auVar35 [16];
  byte *pbStack396;
  byte *pbStack392;
  byte *pbStack388;
  byte bStack377;
  int *piStack376;
  undefined4 uStack372;
  int **ppiStack368;
  byte *pbStack364;
  undefined **ppuStack360;
  undefined *puStack356;
  int **ppiStack352;
  undefined4 uStack348;
  int *piStack344;
  int **ppiStack336;
  int *piStack332;
  undefined **ppuStack328;
  undefined *puStack324;
  int **ppiStack320;
  byte *pbStack316;
  uint *puStack312;
  int *piStack308;
  int **ppiStack304;
  byte bStack297;
  int *piStack296;
  int **ppiStack288;
  int **ppiStack284;
  undefined **ppuStack280;
  undefined *puStack276;
  int **ppiStack272;
  int **ppiStack268;
  int **ppiStack264;
  int **ppiStack256;
  int **ppiStack252;
  int **ppiStack248;
  int **ppiStack244;
  int **ppiStack240;
  int **ppiStack236;
  undefined **ppuStack232;
  int **ppiStack228;
  int **ppiStack224;
  int **ppiStack220;
  int **ppiStack216;
  int iStack212;
  int **ppiStack208;
  int **ppiStack204;
  int iStack200;
  int **ppiStack196;
  undefined auStack192 [16];
  int *piStack176;
  int *piStack172;
  int *piStack168;
  int *piStack164;
  byte bStack153;
  int *piStack152;
  undefined4 uStack148;
  uint uStack144;
  uint *puStack140;
  undefined **ppuStack136;
  undefined **appuStack132 [2];
  int **ppiStack124;
  int **ppiStack120;
  int **ppiStack116;
  byte bStack110;
  byte bStack109;
  undefined uStack108;
  undefined uStack107;
  ushort uStack106;
  int *piStack104;
  undefined4 uStack100;
  undefined *puStack96;
  int iStack92;
  undefined **ppuStack88;
  undefined *apuStack84 [2];
  undefined4 uStack76;
  int *piStack72;
  undefined4 uStack68;
  uint *puStack64;
  ushort *puStack60;
  undefined **ppuStack56;
  undefined *apuStack52 [2];
  int iStack44;
  undefined4 *puStack40;
  int **ppiStack36;
  byte bStack29;
  byte bStack28;
  undefined uStack27;
  ushort uStack26;
  int *piStack24;
  
  apuStack52[0] = &LAB_00014ad1;
  ppiStack36 = (int **)&__stack_chk_guard;
  piStack24 = ___stack_chk_guard;
  puVar26 = &uStack26;
  ppuStack56 = (undefined **)0x2;
  puStack64 = param_1;
  uStack68 = 0x14afc;
  puStack60 = puVar26;
  cVar7 = (**(code **)(param_1[0xe] + 0x2c))();
  if (cVar7 == '\x02') {
    *param_1 = (uint)uStack26;
    ppuStack56 = (undefined **)0x2;
    puStack64 = param_1;
    uStack68 = 0x14b25;
    puStack60 = puVar26;
    cVar7 = (**(code **)(param_1[0xe] + 0x2c))();
    if (cVar7 != '\x02') goto LAB_00014c56;
    param_1[1] = (uint)uStack26;
    puStack60 = (ushort *)&bStack29;
    ppuStack56 = (undefined **)0x3;
    puStack64 = param_1;
    uStack68 = 0x14b53;
    cVar7 = (**(code **)(param_1[0xe] + 0x2c))();
    if (cVar7 != '\x03') {
      param_1[0xc] = 0x66;
      puStack64 = (uint *)param_1[3];
      uStack68 = 0x14b8d;
      FUN_00015c20();
      param_1[3] = 0;
      goto LAB_00014c5d;
    }
    param_1[2] = (uint)bStack28;
    if ((char)bStack29 < '\0') {
      puStack64 = (uint *)(uint)(byte)((bStack29 & 7) + 1);
      puStack60 = (ushort *)0x0;
      uStack68 = 0x14bb6;
      piVar10 = (int *)FUN_00015b90();
      param_1[3] = (uint)piVar10;
      if (piVar10 == (int *)0x0) {
        param_1[0xc] = 0x6d;
        goto LAB_00014c5d;
      }
      uVar15 = 1;
      if (*piVar10 != 0) {
        puVar27 = (uint *)0x0;
        puVar26 = (ushort *)0x2;
        do {
          ppuStack56 = (undefined **)0x3;
          puStack60 = (ushort *)&bStack29;
          puStack64 = param_1;
          uStack68 = 0x14bf6;
          cVar7 = (**(code **)(param_1[0xe] + 0x2c))();
          if (cVar7 != '\x03') {
            puStack64 = (uint *)param_1[3];
            uStack68 = 0x14c4c;
            FUN_00015c20();
            param_1[3] = 0;
            goto LAB_00014c56;
          }
          ppuVar2 = (uint **)param_1[3];
          puVar3 = ppuVar2[2];
          *(byte *)(((int)puVar3 - 2U) + (int)puVar26) = bStack29;
          *(byte *)(((int)puVar3 - 1U) + (int)puVar26) = bStack28;
          *(undefined *)((int)puVar3 + (int)puVar26) = uStack27;
          puVar27 = (uint *)((int)puVar27 + 1);
          puVar26 = (ushort *)((int)puVar26 + 3);
        } while (puVar27 < *ppuVar2);
        uVar15 = 1;
        param_1 = puVar27;
      }
    }
    else {
      param_1[3] = 0;
      uVar15 = 1;
    }
  }
  else {
LAB_00014c56:
    param_1[0xc] = 0x66;
LAB_00014c5d:
    uVar15 = 0;
  }
  if (*ppiStack36 == piStack24) {
    return uVar15;
  }
  apuStack52[0] = (undefined *)0x14c7a;
  func_0x00011af0();
  apuStack84[0] = &LAB_00014c91;
  piStack72 = ___stack_chk_guard;
  iStack92 = (int)&uStack76 + 3;
  ppuStack88 = (undefined **)0x1;
  puStack96 = (undefined *)iStack44;
  uStack100 = 0x14cb8;
  puStack64 = param_1;
  puStack60 = puVar26;
  ppuStack56 = &__DT_PLTGOT;
  apuStack52[0] = &stack0xfffffffc;
  cVar7 = (**(code **)(*(int *)(iStack44 + 0x38) + 0x2c))();
  if (cVar7 == '\x01') {
    if (uStack76._3_1_ == '!') {
      uVar15 = 3;
    }
    else if (uStack76._3_1_ == ';') {
      uVar15 = 4;
    }
    else {
      if (uStack76._3_1_ != ',') {
        *puStack40 = 0;
        *(undefined4 *)(iStack44 + 0x30) = 0x6b;
        goto LAB_00014ce3;
      }
      uVar15 = 2;
    }
    *puStack40 = uVar15;
    uVar15 = 1;
  }
  else {
    *(undefined4 *)(iStack44 + 0x30) = 0x66;
LAB_00014ce3:
    uVar15 = 0;
  }
  if (___stack_chk_guard == piStack72) {
    return uVar15;
  }
  apuStack84[0] = (undefined *)0x14d1e;
  func_0x00011af0();
  iStack92 = iStack44;
  appuStack132[0] = (undefined **)&LAB_00014d31;
  ppiStack124 = (int **)&__stack_chk_guard;
  piStack104 = ___stack_chk_guard;
  ppiStack116 = *(int ***)(uStack76 + 0x38);
  puVar27 = (uint *)&uStack106;
  ppuStack136 = (undefined **)0x2;
  uStack144 = uStack76;
  uStack148 = 0x14d60;
  puStack140 = puVar27;
  puStack96 = &__stack_chk_guard;
  ppuStack88 = &__DT_PLTGOT;
  apuStack84[0] = (undefined *)apuStack52;
  cVar7 = (*(code *)ppiStack116[0xb])();
  if (cVar7 == '\x02') {
    *(uint *)(uStack76 + 0x14) = (uint)uStack106;
    ppuStack136 = (undefined **)0x2;
    uStack144 = uStack76;
    uStack148 = 0x14d8a;
    puStack140 = puVar27;
    cVar7 = (**(code **)(*(int *)(uStack76 + 0x38) + 0x2c))();
    if (cVar7 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack76 + 0x18) = (uint)uStack106;
    ppuStack136 = (undefined **)0x2;
    uStack144 = uStack76;
    uStack148 = 0x14db4;
    puStack140 = puVar27;
    cVar7 = (**(code **)(*(int *)(uStack76 + 0x38) + 0x2c))();
    if (cVar7 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack76 + 0x1c) = (uint)uStack106;
    ppuStack136 = (undefined **)0x2;
    uStack144 = uStack76;
    uStack148 = 0x14dde;
    puStack140 = puVar27;
    cVar7 = (**(code **)(*(int *)(uStack76 + 0x38) + 0x2c))();
    if (cVar7 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack76 + 0x20) = (uint)uStack106;
    puStack140 = (uint *)&bStack109;
    ppuStack136 = (undefined **)0x1;
    uStack144 = uStack76;
    uStack148 = 0x14e0c;
    cVar7 = (**(code **)(*(int *)(uStack76 + 0x38) + 0x2c))();
    if (cVar7 != '\x01') {
      *(undefined4 *)(uStack76 + 0x30) = 0x66;
      uStack144 = *(uint *)(uStack76 + 0x28);
      uStack148 = 0x14f38;
      FUN_00015c20();
LAB_00014f3b:
      *(undefined4 *)(uStack76 + 0x28) = 0;
      goto LAB_00014f0c;
    }
    *(byte *)(uStack76 + 0x24) = bStack109 >> 6 & 1;
    uStack144 = *(int *)(uStack76 + 0x28);
    ppiStack120._0_1_ = bStack109;
    if (uStack144 != 0) {
      ppiStack120 = (int **)((uint)ppiStack120 & 0xffffff00 | (uint)bStack109);
      uStack148 = 0x14e3b;
      FUN_00015c20();
      *(undefined4 *)(uStack76 + 0x28) = 0;
    }
    if ((char)bStack109 < '\0') {
      uStack144 = (uint)(byte)(((byte)ppiStack120 & 7) + 1);
      puStack140 = (uint *)0x0;
      uStack148 = 0x14f5f;
      piVar10 = (int *)FUN_00015b90();
      *(int **)(uStack76 + 0x28) = piVar10;
      if (piVar10 != (int *)0x0) {
        if (*piVar10 != 0) {
          ppiVar9 = (int **)0x0;
          puVar27 = (uint *)0x2;
          do {
            ppuStack136 = (undefined **)0x3;
            puStack140 = (uint *)&bStack109;
            uStack144 = uStack76;
            uStack148 = 0x14f8e;
            ppiStack120 = ppiVar9;
            cVar7 = (**(code **)(*(int *)(uStack76 + 0x38) + 0x2c))();
            if (cVar7 != '\x03') {
              uStack144 = *(uint *)(uStack76 + 0x28);
              uStack148 = 0x15055;
              FUN_00015c20();
              *(undefined4 *)(uStack76 + 0x30) = 0x66;
              goto LAB_00014f3b;
            }
            puVar5 = *(undefined4 **)(uStack76 + 0x28);
            iVar13 = puVar5[2];
            *(byte *)(iVar13 + -2 + (int)puVar27) = bStack109;
            *(undefined *)(iVar13 + -1 + (int)puVar27) = uStack108;
            *(undefined *)(iVar13 + (int)puVar27) = uStack107;
            ppiVar9 = (int **)((int)ppiStack120 + 1);
            puVar27 = (uint *)((int)puVar27 + 3);
          } while (ppiVar9 < (int **)*puVar5);
        }
        goto LAB_00014e55;
      }
LAB_00014fca:
      *(undefined4 *)(uStack76 + 0x30) = 0x6d;
      goto LAB_00014f0c;
    }
LAB_00014e55:
    if ((char)piStack72 != '\0') {
      puStack140 = (uint *)(*(int *)(uStack76 + 0x10) + 1);
      ppuStack136 = (undefined **)0x18;
      uStack144 = *(uint *)(uStack76 + 0x2c);
      uStack148 = 0x14e6e;
      ppiVar9 = (int **)FUN_00015cf0();
      if (ppiVar9 == (int **)0x0) goto LAB_00014fca;
      *(int ***)(uStack76 + 0x2c) = ppiVar9;
      iVar13 = *(int *)(uStack76 + 0x10);
      puVar27 = (uint *)(iVar13 * 3);
      *(undefined8 *)(ppiVar9 + iVar13 * 6 + 4) = *(undefined8 *)(uStack76 + 0x24);
      uVar1 = *(undefined8 *)(uStack76 + 0x14);
      *(undefined8 *)(ppiVar9 + iVar13 * 6 + 2) = *(undefined8 *)(uStack76 + 0x1c);
      *(undefined8 *)(ppiVar9 + iVar13 * 6) = uVar1;
      iVar4 = *(int *)(uStack76 + 0x28);
      if (iVar4 != 0) {
        uStack144 = (uint)*(byte *)(iVar4 + 4);
        puStack140 = *(uint **)(iVar4 + 8);
        uStack148 = 0x14ebf;
        ppiStack120 = ppiVar9;
        piVar10 = (int *)FUN_00015b90();
        ppiStack120[iVar13 * 6 + 5] = piVar10;
        if (piVar10 == (int *)0x0) goto LAB_00014fca;
      }
      *(int *)(uStack76 + 0x10) = *(int *)(uStack76 + 0x10) + 1;
    }
    ppiStack116[10] = (int *)(*(int *)(uStack76 + 0x20) * *(int *)(uStack76 + 0x1c));
    puVar27 = *(uint **)(uStack76 + 0x38);
    puStack140 = (uint *)&bStack110;
    ppuStack136 = (undefined **)0x1;
    uStack144 = uStack76;
    uStack148 = 0x14ef4;
    (*(code *)puVar27[0xb])();
    uVar16 = (uint)bStack110;
    if (8 < uVar16) goto LAB_00014f05;
    *(undefined *)(puVar27 + 0xc) = 0;
    *puVar27 = uVar16;
    uVar17 = 1 << (bStack110 & 0x1f);
    puVar27[1] = uVar17;
    puVar27[2] = uVar17 + 1;
    uVar15 = 1;
    puVar27[3] = uVar17 + 2;
    puVar27[4] = uVar16 + 1;
    puVar27[5] = 2 << (bStack110 & 0x1f);
    *(undefined (*) [16])(puVar27 + 6) = ZEXT416(0x1002);
    iVar13 = -0x1000;
    do {
      puVar3 = puVar27 + iVar13 + 0x184c;
      *puVar3 = 0x1002;
      puVar3[1] = 0x1002;
      puVar3[2] = 0x1002;
      puVar3[3] = 0x1002;
      puVar3 = puVar27 + iVar13 + 0x1850;
      *puVar3 = 0x1002;
      puVar3[1] = 0x1002;
      puVar3[2] = 0x1002;
      puVar3[3] = 0x1002;
      iVar13 = iVar13 + 8;
    } while (iVar13 != 0);
  }
  else {
LAB_00014f05:
    *(undefined4 *)(uStack76 + 0x30) = 0x66;
LAB_00014f0c:
    uVar15 = 0;
  }
  if (*ppiStack124 == piStack104) {
    return uVar15;
  }
  appuStack132[0] = (undefined **)0x15069;
  func_0x00011af0();
  uStack144 = uStack76;
  ppuStack232 = &__DT_PLTGOT;
  piStack152 = ___stack_chk_guard;
  ppiStack284 = (int **)ppiStack124[0xe];
  ppiStack252 = ppiStack116;
  if (ppiStack116 == (int **)0x0) {
    ppiStack252 = (int **)ppiStack124[7];
  }
  piVar10 = ppiStack284[10];
  ppiStack284[10] = (int *)((int)piVar10 - (int)ppiStack252);
  auVar35 = _UNK_00017f30;
  ppiStack288 = ppiStack252;
  ppiVar9 = (int **)&__stack_chk_guard;
  puStack140 = puVar27;
  ppuStack136 = &__DT_PLTGOT;
  if ((int *)((int)piVar10 - (int)ppiStack252) < (int *)0xffff0001) {
    ppiVar28 = (int **)ppiStack284[7];
    uVar15 = 0;
    appuStack132[0] = apuStack84;
    if ((int)ppiVar28 < 0x1000) {
      ppiStack220 = (int **)ppiStack284[1];
      ppiStack196 = (int **)ppiStack284[2];
      ppiVar12 = (int **)ppiStack284[6];
      if (ppiVar28 == (int **)0x0) {
        ppiVar9 = (int **)0x0;
        ppiStack244 = (int **)0x0;
      }
      else if (ppiStack252 == (int **)0x0) {
        ppiVar9 = (int **)0x0;
        ppiStack244 = ppiVar28;
      }
      else {
        uVar20 = -(int)ppiStack252;
        uVar17 = -(int)ppiVar28;
        uVar16 = uVar17;
        if (uVar17 <= uVar20 && ppiVar28 != ppiStack252) {
          uVar16 = uVar20;
        }
        ppiVar11 = (int **)-uVar16;
        ppiVar9 = (int **)0x0;
        if ((int **)0x1f < ppiVar11) {
          if (uVar17 <= uVar20 && ppiVar28 != ppiStack252) {
            uVar17 = uVar20;
          }
          if (((int **)((int)(ppiStack284 + 0x4c) + (int)ppiVar28) <= ppiStack120) ||
             ((int)ppiStack120 - uVar17 <= (int)ppiStack284 + (int)ppiVar28 + uVar17 + 0x130)) {
            ppiVar9 = (int **)((uint)ppiVar11 & 0xffffffe0);
            pauVar19 = (undefined (*) [16])(ppiStack120 + 4);
            pauVar21 = (undefined (*) [16])((int)(ppiStack284 + 0x48) + (int)ppiVar28);
            ppiVar28 = (int **)((int)ppiVar28 - (int)ppiVar9);
            ppiStack288 = ppiVar9;
            do {
              auVar31 = pshufb(*pauVar21,auVar35);
              auVar30 = pshufb(pauVar21[-1],auVar35);
              pauVar19[-1] = auVar31;
              *pauVar19 = auVar30;
              pauVar19 = pauVar19[2];
              pauVar21 = pauVar21[-2];
              ppiStack288 = ppiStack288 + -8;
            } while (ppiStack288 != (int **)0x0);
            ppiStack244 = ppiVar28;
            ppiStack256 = ppiStack284;
            if (ppiVar9 == ppiVar11) goto LAB_00015209;
          }
        }
        do {
          *(undefined *)((int)ppiStack120 + (int)ppiVar9) =
               *(undefined *)((int)ppiStack284 + 0x12f + (int)ppiVar28);
          ppiStack244 = (int **)((int)ppiVar28 + -1);
          ppiVar9 = (int **)((int)ppiVar9 + 1);
          ppiStack288 = ppiStack120;
          ppiStack256 = ppiStack284;
          if (ppiStack252 <= ppiVar9) break;
          bVar29 = ppiVar28 != (int **)0x1;
          ppiVar28 = ppiStack244;
        } while (bVar29);
      }
LAB_00015209:
      ppiStack240 = (int **)&__stack_chk_guard;
      appuStack132[0] = apuStack84;
      if (ppiVar9 < ppiStack252) {
        iStack212 = (int)ppiStack284 + 0x131;
        ppiStack204 = ppiStack120 + 4;
        iStack200 = (int)ppiStack284 + 0x121;
        piVar10 = (int *)0x1002;
        piVar32 = (int *)0x1002;
        piVar33 = (int *)0x1002;
        piVar34 = (int *)0x1002;
        auStack192 = _UNK_00017f30;
        auVar35 = _UNK_00017f30;
        ppiStack256 = ppiStack284;
        ppiStack228 = ppiVar12;
        piStack176 = piVar10;
        piStack172 = piVar32;
        piStack168 = piVar33;
        piStack164 = piVar34;
        appuStack132[0] = apuStack84;
        do {
          ppiStack284 = (int **)ppiStack124[0xe];
          piVar22 = ppiStack284[4];
          if ((int *)0xc < piVar22) {
            ppiStack124[0xc] = (int *)0x70;
            ppiStack288 = ppiStack124;
            goto LAB_00015824;
          }
          piVar18 = ppiStack284[8];
          ppiStack248 = ppiVar9;
          if (piVar18 < piVar22) {
            ppiStack236 = ppiStack284 + 0xc;
            ppiStack224 = (int **)((int)ppiStack284 + 0x31);
            cVar7 = *(char *)(ppiStack284 + 0xc);
            do {
              ppiStack288 = ppiStack236;
              if (cVar7 == '\0') {
                ppiStack268 = ppiStack236;
                ppiStack272 = ppiStack124;
                ppiStack264 = (int **)0x1;
                puStack276 = (undefined *)0x152d2;
                cVar7 = (*(code *)ppiStack124[0xe][0xb])();
                ppiVar9 = ppiStack124;
                if (cVar7 != '\x01') {
                  ppiStack124[0xc] = (int *)0x66;
                  goto LAB_00015824;
                }
                if (*(byte *)ppiStack288 == 0) goto LAB_000157e6;
                ppiStack264 = (int **)(uint)*(byte *)ppiStack288;
                ppiStack268 = ppiStack224;
                ppiStack272 = ppiStack124;
                puStack276 = (undefined *)0x15300;
                uVar16 = (*(code *)ppiStack124[0xe][0xb])();
                if ((char)uVar16 != *(char *)ppiStack236) goto LAB_000157dd;
                bVar8 = *(byte *)((int)ppiStack284 + 0x31);
                *(undefined *)((int)ppiStack284 + 0x31) = 2;
                piVar22 = ppiStack284[4];
                piVar18 = ppiStack284[8];
                auVar35 = auStack192;
                piVar10 = piStack176;
                piVar32 = piStack172;
                piVar33 = piStack168;
                piVar34 = piStack164;
              }
              else {
                bVar8 = *(byte *)((int)ppiStack284 + 0x31);
                uVar16 = (uint)CONCAT11(bVar8 + 1,cVar7);
                *(char *)((int)ppiStack284 + 0x31) = (char)(uVar16 >> 8);
                bVar8 = *(byte *)((int)ppiStack284 + bVar8 + 0x30);
              }
              cVar7 = (char)uVar16 + -1;
              *(char *)(ppiStack284 + 0xc) = cVar7;
              piVar23 = (int *)((uint)bVar8 << ((byte)piVar18 & 0x1f) | (uint)ppiStack284[9]);
              ppiStack284[9] = piVar23;
              piVar18 = piVar18 + 2;
              ppiStack284[8] = piVar18;
            } while (piVar18 < piVar22);
          }
          else {
            piVar23 = ppiStack284[9];
          }
          ppiVar12 = (int **)((uint)*(ushort *)((int)ppuStack232 + (int)piVar22 * 2 + -0x2fe4) &
                             (uint)piVar23);
          ppiStack284[9] = (int *)((uint)piVar23 >> ((byte)piVar22 & 0x1f));
          ppiStack284[8] = (int *)((int)piVar18 - (int)piVar22);
          if (ppiStack284[3] < (int *)0x1001) {
            piVar18 = (int *)((int)ppiStack284[3] + 1);
            ppiStack284[3] = piVar18;
            if ((piVar22 < (int *)0xc) && (ppiStack284[5] < piVar18)) {
              ppiStack284[5] = (int *)((int)ppiStack284[5] * 2);
              ppiStack284[4] = (int *)((int)piVar22 + 1);
            }
          }
          ppiStack288 = ppiStack124;
          if (ppiVar12 == ppiStack196) {
            ppiStack124[0xc] = (int *)0x71;
            goto LAB_00015824;
          }
          if (ppiVar12 == ppiStack220) {
            iVar13 = -0x1000;
            do {
              ppiVar9 = ppiStack256 + iVar13 + 0x184c;
              *ppiVar9 = piVar10;
              ppiVar9[1] = piVar32;
              ppiVar9[2] = piVar33;
              ppiVar9[3] = piVar34;
              ppiVar9 = ppiStack256 + iVar13 + 0x1850;
              *ppiVar9 = piVar10;
              ppiVar9[1] = piVar32;
              ppiVar9[2] = piVar33;
              ppiVar9[3] = piVar34;
              iVar13 = iVar13 + 8;
            } while (iVar13 != 0);
            ppiStack256[3] = (int *)((int)ppiStack256[2] + 1);
            ppiStack256[4] = (int *)((int)*ppiStack256 + 1);
            ppiStack256[5] = (int *)(1 << ((byte)(int *)((int)*ppiStack256 + 1) & 0x1f));
            ppiStack256[6] = (int *)0x1002;
            ppiVar12 = (int **)0x1002;
          }
          else {
            ppiStack236 = ppiVar12;
            if ((int)ppiStack220 <= (int)ppiVar12) {
              ppiVar9 = ppiVar12;
              ppiVar28 = ppiStack244;
              if (ppiStack256[(int)(ppiVar12 + 0x213)] == (int *)0x1002) {
                if (ppiVar12 != (int **)((int)ppiStack256[3] + -2)) {
                  ppiStack124[0xc] = (int *)0x70;
                  ppiVar9 = ppiStack240;
                  goto LAB_000150c5;
                }
                ppiVar9 = ppiStack228;
                if ((int)ppiStack220 < (int)ppiStack228) {
                  iVar13 = 1;
                  while ((int)ppiVar9 < 0x1000) {
                    ppiVar9 = (int **)ppiStack256[(int)(ppiVar9 + 0x213)];
                    if ((0xfff < iVar13) ||
                       (iVar13 = iVar13 + (uint)((int)ppiStack220 < (int)ppiVar9),
                       (int)ppiVar9 <= (int)ppiStack220)) goto LAB_0001556c;
                  }
                  ppiVar9 = (int **)0x1002;
                }
LAB_0001556c:
                *(char *)((int)(ppiStack256 + 0x4c) + (int)ppiStack244) = (char)ppiVar9;
                *(char *)((int)ppiStack256 + 0x112d + (int)ppiStack256[3]) = (char)ppiVar9;
                ppiStack284 = ppiStack228;
                ppiVar9 = ppiStack228;
                ppiVar28 = (int **)((int)ppiStack244 + 1);
                ppiStack288 = ppiStack256;
              }
              if ((int)ppiVar28 < 0xfff) {
                pauVar19 = (undefined (*) [16])(iStack200 + (int)ppiVar28);
                ppiStack284 = (int **)~(uint)ppiVar28;
                while (((int)ppiStack220 < (int)ppiVar9 && ((int)ppiVar9 < 0x1000))) {
                  *(undefined *)((int)(ppiStack256 + 0x4c) + (int)ppiVar28) =
                       *(undefined *)((int)ppiStack256 + 0x112f + (int)ppiVar9);
                  ppiVar9 = (int **)ppiStack256[(int)(ppiVar9 + 0x213)];
                  pauVar19 = (undefined (*) [16])(*pauVar19 + 1);
                  ppiStack284 = (int **)((int)ppiStack284 + -1);
                  bVar29 = 0xffd < (int)ppiVar28;
                  ppiVar28 = (int **)((int)ppiVar28 + 1);
                  ppiStack288 = ppiStack256;
                  if (bVar29) goto LAB_000157e6;
                }
                if ((int)ppiVar9 < 0x1000) {
                  ppiVar11 = (int **)((int)ppiVar28 + 1);
                  *(char *)((int)(ppiStack256 + 0x4c) + (int)ppiVar28) = (char)ppiVar9;
                  ppiVar9 = (int **)((int)ppiStack248 - (int)ppiStack252);
                  ppiStack244 = ppiVar11;
                  if ((ppiStack248 < ppiStack252) && (ppiVar11 != (int **)0x0)) {
                    ppiVar24 = (int **)~(uint)ppiVar28;
                    ppiVar14 = ppiVar24;
                    if (ppiVar24 < ppiVar9) {
                      ppiVar14 = ppiVar9;
                    }
                    ppiVar14 = (int **)-(int)ppiVar14;
                    if ((int **)0x1f < ppiVar14) {
                      ppiStack224 = (int **)((int)ppiStack120 + (int)ppiStack248);
                      ppiVar25 = ppiVar24;
                      if (ppiVar24 < ppiVar9) {
                        ppiVar25 = ppiVar9;
                      }
                      ppiStack216 = ppiVar14;
                      ppiStack208 = ppiVar24;
                      if (((int **)(iStack212 + (int)ppiVar28) <= ppiStack224) ||
                         ((uint)(((int)ppiStack248 - (int)ppiVar25) + (int)ppiStack120) <=
                          (uint)((int)ppiVar28 + (int)ppiVar25 + iStack212))) {
                        ppiStack224 = (int **)((uint)ppiVar14 & 0xffffffe0);
                        ppiVar11 = (int **)((int)ppiVar11 - (int)ppiStack224);
                        pauVar21 = (undefined (*) [16])((int)ppiStack204 + (int)ppiStack248);
                        ppiStack248 = (int **)((int)ppiStack248 + (int)ppiStack224);
                        if (ppiVar9 < ppiStack284) {
                          ppiVar9 = ppiStack284;
                        }
                        uVar16 = -(int)ppiVar9 & 0xffffffe0;
                        do {
                          auVar31 = pshufb(*pauVar19,auVar35);
                          auVar30 = pshufb(pauVar19[-1],auVar35);
                          pauVar21[-1] = auVar31;
                          *pauVar21 = auVar30;
                          pauVar21 = pauVar21[2];
                          pauVar19 = pauVar19[-2];
                          uVar16 = uVar16 - 0x20;
                        } while (uVar16 != 0);
                        ppiStack244 = ppiVar11;
                        if (ppiStack224 == ppiVar14) goto LAB_00015416;
                      }
                    }
                    do {
                      *(undefined *)((int)ppiStack120 + (int)ppiStack248) =
                           *(undefined *)((int)ppiStack256 + 0x12f + (int)ppiVar11);
                      ppiStack244 = (int **)((int)ppiVar11 + -1);
                      ppiStack248 = (int **)((int)ppiStack248 + 1);
                      if (ppiStack252 <= ppiStack248) break;
                      bVar29 = ppiVar11 != (int **)0x1;
                      ppiVar11 = ppiStack244;
                    } while (bVar29);
                  }
                  goto LAB_00015416;
                }
              }
LAB_000157e6:
              ppiStack124[0xc] = (int *)0x70;
              goto LAB_00015824;
            }
            *(char *)((int)ppiStack120 + (int)ppiStack248) = (char)ppiVar12;
            ppiStack248 = (int **)((int)ppiStack248 + 1);
LAB_00015416:
            if ((ppiStack228 != (int **)0x1002) &&
               (ppiStack256[(int)ppiStack256[3] + 0x84a] == (int *)0x1002)) {
              ppiStack256[(int)ppiStack256[3] + 0x84a] = (int *)ppiStack228;
              if (ppiVar12 != (int **)((int)ppiStack256[3] + -2)) {
                ppiStack228 = ppiVar12;
              }
              if ((int)ppiStack220 < (int)ppiStack228) {
                iVar13 = 1;
                while ((int)ppiStack228 < 0x1000) {
                  ppiStack228 = (int **)ppiStack256[(int)(ppiStack228 + 0x213)];
                  if ((0xfff < iVar13) ||
                     (iVar13 = iVar13 + (uint)((int)ppiStack220 < (int)ppiStack228),
                     (int)ppiStack228 <= (int)ppiStack220)) goto LAB_0001572a;
                }
                ppiStack228 = (int **)0x1002;
              }
LAB_0001572a:
              *(char *)((int)ppiStack256 + 0x112f + (int)(int **)((int)ppiStack256[3] + -2)) =
                   (char)ppiStack228;
            }
          }
          ppiVar9 = ppiStack248;
          ppiStack288 = ppiStack124;
          ppiStack284 = ppiStack256;
          ppiStack228 = ppiVar12;
        } while (ppiStack248 < ppiStack252);
      }
      ppiStack284[6] = (int *)ppiVar12;
      ppiStack284[7] = (int *)ppiStack244;
      uVar15 = 1;
      ppiVar9 = ppiStack240;
      ppiStack228 = ppiVar12;
      if (ppiStack284[10] == (int *)0x0) {
        ppiStack284 = (int **)ppiStack124[0xe];
        ppiStack288 = ppiStack124;
        while( true ) {
          ppiStack268 = (int **)&bStack153;
          ppiStack264 = (int **)0x1;
          puStack276 = (undefined *)0x157a9;
          ppiStack272 = ppiStack288;
          cVar7 = (*(code *)ppiStack284[0xb])();
          ppiVar28 = ppiStack124;
          ppiVar9 = ppiStack288;
          if (cVar7 != '\x01') break;
          if (bStack153 == 0) {
            *(undefined *)(ppiStack284 + 0xc) = 0;
            ppiStack284[10] = (int *)0x0;
            uVar15 = 1;
            ppiVar9 = ppiStack240;
            goto LAB_0001582a;
          }
          *(byte *)(ppiStack284 + 0xc) = bStack153;
          ppiStack284 = (int **)((int)ppiStack284 + 0x31);
          ppiStack264 = (int **)(uint)bStack153;
          ppiStack272 = ppiStack124;
          puStack276 = (undefined *)0x157d7;
          ppiStack268 = ppiStack284;
          bVar8 = (*(code *)ppiStack124[0xe][0xb])();
          ppiVar9 = ppiVar28;
          if (bVar8 != bStack153) break;
          ppiStack284 = (int **)ppiVar28[0xe];
          ppiStack288 = ppiVar28;
        }
LAB_000157dd:
        ppiVar9[0xc] = (int *)0x66;
        ppiStack288 = ppiVar9;
LAB_00015824:
        uVar15 = 0;
        ppiVar9 = ppiStack240;
      }
    }
  }
  else {
    ppiStack124[0xc] = (int *)0x6c;
    appuStack132[0] = apuStack84;
LAB_000150c5:
    uVar15 = 0;
  }
LAB_0001582a:
  ppuStack280 = ppuStack232;
  if (*ppiVar9 == piStack152) {
    return uVar15;
  }
  puStack276 = (undefined *)0x15852;
  func_0x00011af0();
  ppiStack336 = ppiStack268;
  ppuStack328 = &__DT_PLTGOT;
  ppiStack304 = (int **)&__stack_chk_guard;
  piStack296 = ___stack_chk_guard;
  piStack332 = ppiStack268[0xe];
  pbStack316 = &bStack297;
  ppiStack320 = ppiStack268;
  puStack312 = (uint *)0x1;
  puStack324 = (undefined *)0x158a4;
  puStack276 = (undefined *)appuStack132;
  cVar7 = (*(code *)piStack332[0xb])();
  if (cVar7 == '\x01') {
    if (bStack297 == 0) {
      *ppiStack264 = (int *)0x0;
      *(undefined *)(piStack332 + 0xc) = 0;
      piStack332[10] = 0;
      uVar15 = 1;
    }
    else {
      *ppiStack264 = piStack332 + 0xc;
      *(byte *)(piStack332 + 0xc) = bStack297;
      pbStack316 = (byte *)((int)*ppiStack264 + 1);
      puStack312 = (uint *)(uint)bStack297;
      ppiStack320 = ppiStack336;
      puStack324 = (undefined *)0x158d2;
      bVar8 = (*(code *)ppiStack336[0xe][0xb])();
      uVar15 = 1;
      if (bVar8 != bStack297) goto LAB_000158df;
    }
  }
  else {
LAB_000158df:
    ppiStack336[0xc] = (int *)0x66;
    uVar15 = 0;
  }
  if (*ppiStack304 == piStack296) {
    return uVar15;
  }
  puStack324 = (undefined *)0x15919;
  func_0x00011af0();
  pbVar6 = pbStack316;
  puStack356 = &LAB_00015931;
  piStack344 = ___stack_chk_guard;
  pbStack364 = (byte *)((int)&uStack348 + 2);
  ppuStack360 = (undefined **)0x1;
  ppiStack368 = (int **)pbStack316;
  uStack372 = 0x15958;
  puStack324 = (undefined *)&puStack276;
  cVar7 = (**(code **)(*(int *)(pbStack316 + 0x38) + 0x2c))();
  ppiVar9 = (int **)&__stack_chk_guard;
  if (cVar7 == '\x01') {
    *puStack312 = uStack348 >> 0x10 & 0xff;
    iVar13 = *(int *)(pbVar6 + 0x38);
    pbStack364 = (byte *)((int)&uStack348 + 3);
    ppuStack360 = (undefined **)0x1;
    ppiStack368 = (int **)pbVar6;
    uStack372 = 0x1597d;
    ppiStack352 = (int **)&__stack_chk_guard;
    cVar7 = (**(code **)(iVar13 + 0x2c))();
    ppiVar9 = ppiStack352;
    if (cVar7 == '\x01') {
      if (uStack348._3_1_ == 0) {
        *piStack308 = 0;
        uVar15 = 1;
      }
      else {
        *piStack308 = iVar13 + 0x30;
        *(byte *)(iVar13 + 0x30) = uStack348._3_1_;
        pbStack364 = (byte *)(*piStack308 + 1);
        ppuStack360 = (undefined **)(uint)uStack348._3_1_;
        ppiStack368 = (int **)pbVar6;
        uStack372 = 0x159b1;
        cVar7 = (**(code **)(*(int *)(pbVar6 + 0x38) + 0x2c))();
        uVar15 = 1;
        ppiVar9 = ppiStack352;
        if (cVar7 != uStack348._3_1_) goto LAB_000159c4;
      }
    }
    else {
      *(undefined4 *)(pbVar6 + 0x30) = 0x66;
      uVar15 = 0;
    }
  }
  else {
LAB_000159c4:
    *(undefined4 *)(pbVar6 + 0x30) = 0x66;
    uVar15 = 0;
  }
  if (*ppiVar9 == piStack344) {
    return uVar15;
  }
  puStack356 = (undefined *)0x159fd;
  func_0x00011af0();
  pbStack364 = pbVar6;
  piStack376 = ___stack_chk_guard;
  iVar13 = *(int *)(uStack348 + 0x38);
  pbStack396 = &bStack377;
  pbStack392 = (byte *)0x1;
  ppiStack368 = ppiVar9;
  ppuStack360 = &__DT_PLTGOT;
  puStack356 = (undefined *)&puStack324;
  cVar7 = (**(code **)(iVar13 + 0x2c))(uStack348);
  if (cVar7 == '\x01') {
    if (bStack377 == 0) {
      *piStack344 = 0;
      uVar15 = 1;
      goto LAB_00015a95;
    }
    *piStack344 = iVar13 + 0x30;
    *(byte *)(iVar13 + 0x30) = bStack377;
    pbStack396 = (byte *)(*piStack344 + 1);
    pbStack392 = (byte *)(uint)bStack377;
    bVar8 = (**(code **)(*(int *)(uStack348 + 0x38) + 0x2c))(uStack348);
    uVar15 = 1;
    if (bVar8 == bStack377) goto LAB_00015a95;
  }
  *(undefined4 *)(uStack348 + 0x30) = 0x66;
  uVar15 = 0;
LAB_00015a95:
  if (___stack_chk_guard != piStack376) {
    func_0x00011af0();
    uVar15 = 0;
    if (pbStack396 == (byte *)0x4) {
      *pbStack388 = *pbStack392 >> 2 & 7;
      *(uint *)(pbStack388 + 4) = (uint)*(ushort *)(pbStack392 + 1);
      uVar16 = 0xffffffff;
      if ((*pbStack392 & 1) != 0) {
        uVar16 = (uint)pbStack392[3];
      }
      *(uint *)(pbStack388 + 8) = uVar16;
      uVar15 = 1;
    }
    return uVar15;
  }
  return uVar15;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00014c80(int param_1,undefined4 *param_2)

{
  uint *puVar1;
  undefined8 uVar2;
  int iVar3;
  undefined4 *puVar4;
  byte *pbVar5;
  char cVar6;
  byte bVar7;
  int **ppiVar8;
  int *piVar9;
  int **ppiVar10;
  int **ppiVar11;
  int iVar12;
  int **ppiVar13;
  undefined4 uVar14;
  uint uVar15;
  uint uVar16;
  int *piVar17;
  undefined (*pauVar18) [16];
  uint uVar19;
  undefined (*pauVar20) [16];
  int *piVar21;
  int *piVar22;
  int **ppiVar23;
  int **ppiVar24;
  uint *puVar25;
  int **ppiVar26;
  bool bVar27;
  undefined auVar28 [16];
  undefined auVar29 [16];
  int *piVar30;
  int *piVar31;
  int *piVar32;
  undefined auVar33 [16];
  byte *pbStack348;
  byte *pbStack344;
  byte *pbStack340;
  byte bStack329;
  int *piStack328;
  undefined4 uStack324;
  int **ppiStack320;
  byte *pbStack316;
  undefined **ppuStack312;
  undefined *puStack308;
  int **ppiStack304;
  undefined4 uStack300;
  int *piStack296;
  int **ppiStack288;
  int *piStack284;
  undefined **ppuStack280;
  undefined *puStack276;
  int **ppiStack272;
  byte *pbStack268;
  uint *puStack264;
  int *piStack260;
  int **ppiStack256;
  byte bStack249;
  int *piStack248;
  int **ppiStack240;
  int **ppiStack236;
  undefined **ppuStack232;
  undefined *puStack228;
  int **ppiStack224;
  int **ppiStack220;
  int **ppiStack216;
  int **ppiStack208;
  int **ppiStack204;
  int **ppiStack200;
  int **ppiStack196;
  int **ppiStack192;
  int **ppiStack188;
  undefined **ppuStack184;
  int **ppiStack180;
  int **ppiStack176;
  int **ppiStack172;
  int **ppiStack168;
  int iStack164;
  int **ppiStack160;
  int **ppiStack156;
  int iStack152;
  int **ppiStack148;
  undefined auStack144 [16];
  int *piStack128;
  int *piStack124;
  int *piStack120;
  int *piStack116;
  byte bStack105;
  int *piStack104;
  undefined4 uStack100;
  uint uStack96;
  uint *puStack92;
  undefined **ppuStack88;
  undefined **appuStack84 [2];
  int **ppiStack76;
  int **ppiStack72;
  int **ppiStack68;
  byte bStack62;
  byte bStack61;
  undefined uStack60;
  undefined uStack59;
  ushort uStack58;
  int *piStack56;
  undefined4 uStack52;
  undefined *puStack48;
  int iStack44;
  undefined **ppuStack40;
  undefined *apuStack36 [2];
  undefined4 uStack28;
  int *piStack24;
  
  apuStack36[0] = &LAB_00014c91;
  piStack24 = ___stack_chk_guard;
  iStack44 = (int)&uStack28 + 3;
  ppuStack40 = (undefined **)0x1;
  puStack48 = (undefined *)param_1;
  uStack52 = 0x14cb8;
  cVar6 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
  if (cVar6 == '\x01') {
    if (uStack28._3_1_ == '!') {
      uVar14 = 3;
    }
    else if (uStack28._3_1_ == ';') {
      uVar14 = 4;
    }
    else {
      if (uStack28._3_1_ != ',') {
        *param_2 = 0;
        *(undefined4 *)(param_1 + 0x30) = 0x6b;
        goto LAB_00014ce3;
      }
      uVar14 = 2;
    }
    *param_2 = uVar14;
    uVar14 = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0x30) = 0x66;
LAB_00014ce3:
    uVar14 = 0;
  }
  if (___stack_chk_guard == piStack24) {
    return uVar14;
  }
  apuStack36[0] = (undefined *)0x14d1e;
  func_0x00011af0();
  iStack44 = param_1;
  appuStack84[0] = (undefined **)&LAB_00014d31;
  ppiStack76 = (int **)&__stack_chk_guard;
  piStack56 = ___stack_chk_guard;
  ppiStack68 = *(int ***)(uStack28 + 0x38);
  puVar25 = (uint *)&uStack58;
  ppuStack88 = (undefined **)0x2;
  uStack96 = uStack28;
  uStack100 = 0x14d60;
  puStack92 = puVar25;
  puStack48 = &__stack_chk_guard;
  ppuStack40 = &__DT_PLTGOT;
  apuStack36[0] = &stack0xfffffffc;
  cVar6 = (*(code *)ppiStack68[0xb])();
  if (cVar6 == '\x02') {
    *(uint *)(uStack28 + 0x14) = (uint)uStack58;
    ppuStack88 = (undefined **)0x2;
    uStack96 = uStack28;
    uStack100 = 0x14d8a;
    puStack92 = puVar25;
    cVar6 = (**(code **)(*(int *)(uStack28 + 0x38) + 0x2c))();
    if (cVar6 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack28 + 0x18) = (uint)uStack58;
    ppuStack88 = (undefined **)0x2;
    uStack96 = uStack28;
    uStack100 = 0x14db4;
    puStack92 = puVar25;
    cVar6 = (**(code **)(*(int *)(uStack28 + 0x38) + 0x2c))();
    if (cVar6 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack28 + 0x1c) = (uint)uStack58;
    ppuStack88 = (undefined **)0x2;
    uStack96 = uStack28;
    uStack100 = 0x14dde;
    puStack92 = puVar25;
    cVar6 = (**(code **)(*(int *)(uStack28 + 0x38) + 0x2c))();
    if (cVar6 != '\x02') goto LAB_00014f05;
    *(uint *)(uStack28 + 0x20) = (uint)uStack58;
    puStack92 = (uint *)&bStack61;
    ppuStack88 = (undefined **)0x1;
    uStack96 = uStack28;
    uStack100 = 0x14e0c;
    cVar6 = (**(code **)(*(int *)(uStack28 + 0x38) + 0x2c))();
    if (cVar6 != '\x01') {
      *(undefined4 *)(uStack28 + 0x30) = 0x66;
      uStack96 = *(uint *)(uStack28 + 0x28);
      uStack100 = 0x14f38;
      FUN_00015c20();
LAB_00014f3b:
      *(undefined4 *)(uStack28 + 0x28) = 0;
      goto LAB_00014f0c;
    }
    *(byte *)(uStack28 + 0x24) = bStack61 >> 6 & 1;
    uStack96 = *(int *)(uStack28 + 0x28);
    ppiStack72._0_1_ = bStack61;
    if (uStack96 != 0) {
      ppiStack72 = (int **)((uint)ppiStack72 & 0xffffff00 | (uint)bStack61);
      uStack100 = 0x14e3b;
      FUN_00015c20();
      *(undefined4 *)(uStack28 + 0x28) = 0;
    }
    if ((char)bStack61 < '\0') {
      uStack96 = (uint)(byte)(((byte)ppiStack72 & 7) + 1);
      puStack92 = (uint *)0x0;
      uStack100 = 0x14f5f;
      piVar9 = (int *)FUN_00015b90();
      *(int **)(uStack28 + 0x28) = piVar9;
      if (piVar9 != (int *)0x0) {
        if (*piVar9 != 0) {
          ppiVar8 = (int **)0x0;
          puVar25 = (uint *)0x2;
          do {
            ppuStack88 = (undefined **)0x3;
            puStack92 = (uint *)&bStack61;
            uStack96 = uStack28;
            uStack100 = 0x14f8e;
            ppiStack72 = ppiVar8;
            cVar6 = (**(code **)(*(int *)(uStack28 + 0x38) + 0x2c))();
            if (cVar6 != '\x03') {
              uStack96 = *(uint *)(uStack28 + 0x28);
              uStack100 = 0x15055;
              FUN_00015c20();
              *(undefined4 *)(uStack28 + 0x30) = 0x66;
              goto LAB_00014f3b;
            }
            puVar4 = *(undefined4 **)(uStack28 + 0x28);
            iVar12 = puVar4[2];
            *(byte *)(iVar12 + -2 + (int)puVar25) = bStack61;
            *(undefined *)(iVar12 + -1 + (int)puVar25) = uStack60;
            *(undefined *)(iVar12 + (int)puVar25) = uStack59;
            ppiVar8 = (int **)((int)ppiStack72 + 1);
            puVar25 = (uint *)((int)puVar25 + 3);
          } while (ppiVar8 < (int **)*puVar4);
        }
        goto LAB_00014e55;
      }
LAB_00014fca:
      *(undefined4 *)(uStack28 + 0x30) = 0x6d;
      goto LAB_00014f0c;
    }
LAB_00014e55:
    if ((char)piStack24 != '\0') {
      puStack92 = (uint *)(*(int *)(uStack28 + 0x10) + 1);
      ppuStack88 = (undefined **)0x18;
      uStack96 = *(uint *)(uStack28 + 0x2c);
      uStack100 = 0x14e6e;
      ppiVar8 = (int **)FUN_00015cf0();
      if (ppiVar8 == (int **)0x0) goto LAB_00014fca;
      *(int ***)(uStack28 + 0x2c) = ppiVar8;
      iVar12 = *(int *)(uStack28 + 0x10);
      puVar25 = (uint *)(iVar12 * 3);
      *(undefined8 *)(ppiVar8 + iVar12 * 6 + 4) = *(undefined8 *)(uStack28 + 0x24);
      uVar2 = *(undefined8 *)(uStack28 + 0x14);
      *(undefined8 *)(ppiVar8 + iVar12 * 6 + 2) = *(undefined8 *)(uStack28 + 0x1c);
      *(undefined8 *)(ppiVar8 + iVar12 * 6) = uVar2;
      iVar3 = *(int *)(uStack28 + 0x28);
      if (iVar3 != 0) {
        uStack96 = (uint)*(byte *)(iVar3 + 4);
        puStack92 = *(uint **)(iVar3 + 8);
        uStack100 = 0x14ebf;
        ppiStack72 = ppiVar8;
        piVar9 = (int *)FUN_00015b90();
        ppiStack72[iVar12 * 6 + 5] = piVar9;
        if (piVar9 == (int *)0x0) goto LAB_00014fca;
      }
      *(int *)(uStack28 + 0x10) = *(int *)(uStack28 + 0x10) + 1;
    }
    ppiStack68[10] = (int *)(*(int *)(uStack28 + 0x20) * *(int *)(uStack28 + 0x1c));
    puVar25 = *(uint **)(uStack28 + 0x38);
    puStack92 = (uint *)&bStack62;
    ppuStack88 = (undefined **)0x1;
    uStack96 = uStack28;
    uStack100 = 0x14ef4;
    (*(code *)puVar25[0xb])();
    uVar15 = (uint)bStack62;
    if (8 < uVar15) goto LAB_00014f05;
    *(undefined *)(puVar25 + 0xc) = 0;
    *puVar25 = uVar15;
    uVar16 = 1 << (bStack62 & 0x1f);
    puVar25[1] = uVar16;
    puVar25[2] = uVar16 + 1;
    uVar14 = 1;
    puVar25[3] = uVar16 + 2;
    puVar25[4] = uVar15 + 1;
    puVar25[5] = 2 << (bStack62 & 0x1f);
    *(undefined (*) [16])(puVar25 + 6) = ZEXT416(0x1002);
    iVar12 = -0x1000;
    do {
      puVar1 = puVar25 + iVar12 + 0x184c;
      *puVar1 = 0x1002;
      puVar1[1] = 0x1002;
      puVar1[2] = 0x1002;
      puVar1[3] = 0x1002;
      puVar1 = puVar25 + iVar12 + 0x1850;
      *puVar1 = 0x1002;
      puVar1[1] = 0x1002;
      puVar1[2] = 0x1002;
      puVar1[3] = 0x1002;
      iVar12 = iVar12 + 8;
    } while (iVar12 != 0);
  }
  else {
LAB_00014f05:
    *(undefined4 *)(uStack28 + 0x30) = 0x66;
LAB_00014f0c:
    uVar14 = 0;
  }
  if (*ppiStack76 == piStack56) {
    return uVar14;
  }
  appuStack84[0] = (undefined **)0x15069;
  func_0x00011af0();
  uStack96 = uStack28;
  ppuStack184 = &__DT_PLTGOT;
  piStack104 = ___stack_chk_guard;
  ppiStack236 = (int **)ppiStack76[0xe];
  ppiStack204 = ppiStack68;
  if (ppiStack68 == (int **)0x0) {
    ppiStack204 = (int **)ppiStack76[7];
  }
  piVar9 = ppiStack236[10];
  ppiStack236[10] = (int *)((int)piVar9 - (int)ppiStack204);
  auVar33 = _UNK_00017f30;
  ppiStack240 = ppiStack204;
  ppiVar8 = (int **)&__stack_chk_guard;
  puStack92 = puVar25;
  ppuStack88 = &__DT_PLTGOT;
  if ((int *)((int)piVar9 - (int)ppiStack204) < (int *)0xffff0001) {
    ppiVar26 = (int **)ppiStack236[7];
    uVar14 = 0;
    appuStack84[0] = apuStack36;
    if ((int)ppiVar26 < 0x1000) {
      ppiStack172 = (int **)ppiStack236[1];
      ppiStack148 = (int **)ppiStack236[2];
      ppiVar11 = (int **)ppiStack236[6];
      if (ppiVar26 == (int **)0x0) {
        ppiVar8 = (int **)0x0;
        ppiStack196 = (int **)0x0;
      }
      else if (ppiStack204 == (int **)0x0) {
        ppiVar8 = (int **)0x0;
        ppiStack196 = ppiVar26;
      }
      else {
        uVar19 = -(int)ppiStack204;
        uVar16 = -(int)ppiVar26;
        uVar15 = uVar16;
        if (uVar16 <= uVar19 && ppiVar26 != ppiStack204) {
          uVar15 = uVar19;
        }
        ppiVar10 = (int **)-uVar15;
        ppiVar8 = (int **)0x0;
        if ((int **)0x1f < ppiVar10) {
          if (uVar16 <= uVar19 && ppiVar26 != ppiStack204) {
            uVar16 = uVar19;
          }
          if (((int **)((int)(ppiStack236 + 0x4c) + (int)ppiVar26) <= ppiStack72) ||
             ((int)ppiStack72 - uVar16 <= (int)ppiStack236 + (int)ppiVar26 + uVar16 + 0x130)) {
            ppiVar8 = (int **)((uint)ppiVar10 & 0xffffffe0);
            pauVar18 = (undefined (*) [16])(ppiStack72 + 4);
            pauVar20 = (undefined (*) [16])((int)(ppiStack236 + 0x48) + (int)ppiVar26);
            ppiVar26 = (int **)((int)ppiVar26 - (int)ppiVar8);
            ppiStack240 = ppiVar8;
            do {
              auVar29 = pshufb(*pauVar20,auVar33);
              auVar28 = pshufb(pauVar20[-1],auVar33);
              pauVar18[-1] = auVar29;
              *pauVar18 = auVar28;
              pauVar18 = pauVar18[2];
              pauVar20 = pauVar20[-2];
              ppiStack240 = ppiStack240 + -8;
            } while (ppiStack240 != (int **)0x0);
            ppiStack196 = ppiVar26;
            ppiStack208 = ppiStack236;
            if (ppiVar8 == ppiVar10) goto LAB_00015209;
          }
        }
        do {
          *(undefined *)((int)ppiStack72 + (int)ppiVar8) =
               *(undefined *)((int)ppiStack236 + 0x12f + (int)ppiVar26);
          ppiStack196 = (int **)((int)ppiVar26 + -1);
          ppiVar8 = (int **)((int)ppiVar8 + 1);
          ppiStack240 = ppiStack72;
          ppiStack208 = ppiStack236;
          if (ppiStack204 <= ppiVar8) break;
          bVar27 = ppiVar26 != (int **)0x1;
          ppiVar26 = ppiStack196;
        } while (bVar27);
      }
LAB_00015209:
      ppiStack192 = (int **)&__stack_chk_guard;
      appuStack84[0] = apuStack36;
      if (ppiVar8 < ppiStack204) {
        iStack164 = (int)ppiStack236 + 0x131;
        ppiStack156 = ppiStack72 + 4;
        iStack152 = (int)ppiStack236 + 0x121;
        piVar9 = (int *)0x1002;
        piVar30 = (int *)0x1002;
        piVar31 = (int *)0x1002;
        piVar32 = (int *)0x1002;
        auStack144 = _UNK_00017f30;
        auVar33 = _UNK_00017f30;
        ppiStack208 = ppiStack236;
        ppiStack180 = ppiVar11;
        piStack128 = piVar9;
        piStack124 = piVar30;
        piStack120 = piVar31;
        piStack116 = piVar32;
        appuStack84[0] = apuStack36;
        do {
          ppiStack236 = (int **)ppiStack76[0xe];
          piVar21 = ppiStack236[4];
          if ((int *)0xc < piVar21) {
            ppiStack76[0xc] = (int *)0x70;
            ppiStack240 = ppiStack76;
            goto LAB_00015824;
          }
          piVar17 = ppiStack236[8];
          ppiStack200 = ppiVar8;
          if (piVar17 < piVar21) {
            ppiStack188 = ppiStack236 + 0xc;
            ppiStack176 = (int **)((int)ppiStack236 + 0x31);
            cVar6 = *(char *)(ppiStack236 + 0xc);
            do {
              ppiStack240 = ppiStack188;
              if (cVar6 == '\0') {
                ppiStack220 = ppiStack188;
                ppiStack224 = ppiStack76;
                ppiStack216 = (int **)0x1;
                puStack228 = (undefined *)0x152d2;
                cVar6 = (*(code *)ppiStack76[0xe][0xb])();
                ppiVar8 = ppiStack76;
                if (cVar6 != '\x01') {
                  ppiStack76[0xc] = (int *)0x66;
                  goto LAB_00015824;
                }
                if (*(byte *)ppiStack240 == 0) goto LAB_000157e6;
                ppiStack216 = (int **)(uint)*(byte *)ppiStack240;
                ppiStack220 = ppiStack176;
                ppiStack224 = ppiStack76;
                puStack228 = (undefined *)0x15300;
                uVar15 = (*(code *)ppiStack76[0xe][0xb])();
                if ((char)uVar15 != *(char *)ppiStack188) goto LAB_000157dd;
                bVar7 = *(byte *)((int)ppiStack236 + 0x31);
                *(undefined *)((int)ppiStack236 + 0x31) = 2;
                piVar21 = ppiStack236[4];
                piVar17 = ppiStack236[8];
                auVar33 = auStack144;
                piVar9 = piStack128;
                piVar30 = piStack124;
                piVar31 = piStack120;
                piVar32 = piStack116;
              }
              else {
                bVar7 = *(byte *)((int)ppiStack236 + 0x31);
                uVar15 = (uint)CONCAT11(bVar7 + 1,cVar6);
                *(char *)((int)ppiStack236 + 0x31) = (char)(uVar15 >> 8);
                bVar7 = *(byte *)((int)ppiStack236 + bVar7 + 0x30);
              }
              cVar6 = (char)uVar15 + -1;
              *(char *)(ppiStack236 + 0xc) = cVar6;
              piVar22 = (int *)((uint)bVar7 << ((byte)piVar17 & 0x1f) | (uint)ppiStack236[9]);
              ppiStack236[9] = piVar22;
              piVar17 = piVar17 + 2;
              ppiStack236[8] = piVar17;
            } while (piVar17 < piVar21);
          }
          else {
            piVar22 = ppiStack236[9];
          }
          ppiVar11 = (int **)((uint)*(ushort *)((int)ppuStack184 + (int)piVar21 * 2 + -0x2fe4) &
                             (uint)piVar22);
          ppiStack236[9] = (int *)((uint)piVar22 >> ((byte)piVar21 & 0x1f));
          ppiStack236[8] = (int *)((int)piVar17 - (int)piVar21);
          if (ppiStack236[3] < (int *)0x1001) {
            piVar17 = (int *)((int)ppiStack236[3] + 1);
            ppiStack236[3] = piVar17;
            if ((piVar21 < (int *)0xc) && (ppiStack236[5] < piVar17)) {
              ppiStack236[5] = (int *)((int)ppiStack236[5] * 2);
              ppiStack236[4] = (int *)((int)piVar21 + 1);
            }
          }
          ppiStack240 = ppiStack76;
          if (ppiVar11 == ppiStack148) {
            ppiStack76[0xc] = (int *)0x71;
            goto LAB_00015824;
          }
          if (ppiVar11 == ppiStack172) {
            iVar12 = -0x1000;
            do {
              ppiVar8 = ppiStack208 + iVar12 + 0x184c;
              *ppiVar8 = piVar9;
              ppiVar8[1] = piVar30;
              ppiVar8[2] = piVar31;
              ppiVar8[3] = piVar32;
              ppiVar8 = ppiStack208 + iVar12 + 0x1850;
              *ppiVar8 = piVar9;
              ppiVar8[1] = piVar30;
              ppiVar8[2] = piVar31;
              ppiVar8[3] = piVar32;
              iVar12 = iVar12 + 8;
            } while (iVar12 != 0);
            ppiStack208[3] = (int *)((int)ppiStack208[2] + 1);
            ppiStack208[4] = (int *)((int)*ppiStack208 + 1);
            ppiStack208[5] = (int *)(1 << ((byte)(int *)((int)*ppiStack208 + 1) & 0x1f));
            ppiStack208[6] = (int *)0x1002;
            ppiVar11 = (int **)0x1002;
          }
          else {
            ppiStack188 = ppiVar11;
            if ((int)ppiStack172 <= (int)ppiVar11) {
              ppiVar8 = ppiVar11;
              ppiVar26 = ppiStack196;
              if (ppiStack208[(int)(ppiVar11 + 0x213)] == (int *)0x1002) {
                if (ppiVar11 != (int **)((int)ppiStack208[3] + -2)) {
                  ppiStack76[0xc] = (int *)0x70;
                  ppiVar8 = ppiStack192;
                  goto LAB_000150c5;
                }
                ppiVar8 = ppiStack180;
                if ((int)ppiStack172 < (int)ppiStack180) {
                  iVar12 = 1;
                  while ((int)ppiVar8 < 0x1000) {
                    ppiVar8 = (int **)ppiStack208[(int)(ppiVar8 + 0x213)];
                    if ((0xfff < iVar12) ||
                       (iVar12 = iVar12 + (uint)((int)ppiStack172 < (int)ppiVar8),
                       (int)ppiVar8 <= (int)ppiStack172)) goto LAB_0001556c;
                  }
                  ppiVar8 = (int **)0x1002;
                }
LAB_0001556c:
                *(char *)((int)(ppiStack208 + 0x4c) + (int)ppiStack196) = (char)ppiVar8;
                *(char *)((int)ppiStack208 + 0x112d + (int)ppiStack208[3]) = (char)ppiVar8;
                ppiStack236 = ppiStack180;
                ppiVar8 = ppiStack180;
                ppiVar26 = (int **)((int)ppiStack196 + 1);
                ppiStack240 = ppiStack208;
              }
              if ((int)ppiVar26 < 0xfff) {
                pauVar18 = (undefined (*) [16])(iStack152 + (int)ppiVar26);
                ppiStack236 = (int **)~(uint)ppiVar26;
                while (((int)ppiStack172 < (int)ppiVar8 && ((int)ppiVar8 < 0x1000))) {
                  *(undefined *)((int)(ppiStack208 + 0x4c) + (int)ppiVar26) =
                       *(undefined *)((int)ppiStack208 + 0x112f + (int)ppiVar8);
                  ppiVar8 = (int **)ppiStack208[(int)(ppiVar8 + 0x213)];
                  pauVar18 = (undefined (*) [16])(*pauVar18 + 1);
                  ppiStack236 = (int **)((int)ppiStack236 + -1);
                  bVar27 = 0xffd < (int)ppiVar26;
                  ppiVar26 = (int **)((int)ppiVar26 + 1);
                  ppiStack240 = ppiStack208;
                  if (bVar27) goto LAB_000157e6;
                }
                if ((int)ppiVar8 < 0x1000) {
                  ppiVar10 = (int **)((int)ppiVar26 + 1);
                  *(char *)((int)(ppiStack208 + 0x4c) + (int)ppiVar26) = (char)ppiVar8;
                  ppiVar8 = (int **)((int)ppiStack200 - (int)ppiStack204);
                  ppiStack196 = ppiVar10;
                  if ((ppiStack200 < ppiStack204) && (ppiVar10 != (int **)0x0)) {
                    ppiVar23 = (int **)~(uint)ppiVar26;
                    ppiVar13 = ppiVar23;
                    if (ppiVar23 < ppiVar8) {
                      ppiVar13 = ppiVar8;
                    }
                    ppiVar13 = (int **)-(int)ppiVar13;
                    if ((int **)0x1f < ppiVar13) {
                      ppiStack176 = (int **)((int)ppiStack72 + (int)ppiStack200);
                      ppiVar24 = ppiVar23;
                      if (ppiVar23 < ppiVar8) {
                        ppiVar24 = ppiVar8;
                      }
                      ppiStack168 = ppiVar13;
                      ppiStack160 = ppiVar23;
                      if (((int **)(iStack164 + (int)ppiVar26) <= ppiStack176) ||
                         ((uint)(((int)ppiStack200 - (int)ppiVar24) + (int)ppiStack72) <=
                          (uint)((int)ppiVar26 + (int)ppiVar24 + iStack164))) {
                        ppiStack176 = (int **)((uint)ppiVar13 & 0xffffffe0);
                        ppiVar10 = (int **)((int)ppiVar10 - (int)ppiStack176);
                        pauVar20 = (undefined (*) [16])((int)ppiStack156 + (int)ppiStack200);
                        ppiStack200 = (int **)((int)ppiStack200 + (int)ppiStack176);
                        if (ppiVar8 < ppiStack236) {
                          ppiVar8 = ppiStack236;
                        }
                        uVar15 = -(int)ppiVar8 & 0xffffffe0;
                        do {
                          auVar29 = pshufb(*pauVar18,auVar33);
                          auVar28 = pshufb(pauVar18[-1],auVar33);
                          pauVar20[-1] = auVar29;
                          *pauVar20 = auVar28;
                          pauVar20 = pauVar20[2];
                          pauVar18 = pauVar18[-2];
                          uVar15 = uVar15 - 0x20;
                        } while (uVar15 != 0);
                        ppiStack196 = ppiVar10;
                        if (ppiStack176 == ppiVar13) goto LAB_00015416;
                      }
                    }
                    do {
                      *(undefined *)((int)ppiStack72 + (int)ppiStack200) =
                           *(undefined *)((int)ppiStack208 + 0x12f + (int)ppiVar10);
                      ppiStack196 = (int **)((int)ppiVar10 + -1);
                      ppiStack200 = (int **)((int)ppiStack200 + 1);
                      if (ppiStack204 <= ppiStack200) break;
                      bVar27 = ppiVar10 != (int **)0x1;
                      ppiVar10 = ppiStack196;
                    } while (bVar27);
                  }
                  goto LAB_00015416;
                }
              }
LAB_000157e6:
              ppiStack76[0xc] = (int *)0x70;
              goto LAB_00015824;
            }
            *(char *)((int)ppiStack72 + (int)ppiStack200) = (char)ppiVar11;
            ppiStack200 = (int **)((int)ppiStack200 + 1);
LAB_00015416:
            if ((ppiStack180 != (int **)0x1002) &&
               (ppiStack208[(int)ppiStack208[3] + 0x84a] == (int *)0x1002)) {
              ppiStack208[(int)ppiStack208[3] + 0x84a] = (int *)ppiStack180;
              if (ppiVar11 != (int **)((int)ppiStack208[3] + -2)) {
                ppiStack180 = ppiVar11;
              }
              if ((int)ppiStack172 < (int)ppiStack180) {
                iVar12 = 1;
                while ((int)ppiStack180 < 0x1000) {
                  ppiStack180 = (int **)ppiStack208[(int)(ppiStack180 + 0x213)];
                  if ((0xfff < iVar12) ||
                     (iVar12 = iVar12 + (uint)((int)ppiStack172 < (int)ppiStack180),
                     (int)ppiStack180 <= (int)ppiStack172)) goto LAB_0001572a;
                }
                ppiStack180 = (int **)0x1002;
              }
LAB_0001572a:
              *(char *)((int)ppiStack208 + 0x112f + (int)(int **)((int)ppiStack208[3] + -2)) =
                   (char)ppiStack180;
            }
          }
          ppiVar8 = ppiStack200;
          ppiStack240 = ppiStack76;
          ppiStack236 = ppiStack208;
          ppiStack180 = ppiVar11;
        } while (ppiStack200 < ppiStack204);
      }
      ppiStack236[6] = (int *)ppiVar11;
      ppiStack236[7] = (int *)ppiStack196;
      uVar14 = 1;
      ppiVar8 = ppiStack192;
      ppiStack180 = ppiVar11;
      if (ppiStack236[10] == (int *)0x0) {
        ppiStack236 = (int **)ppiStack76[0xe];
        ppiStack240 = ppiStack76;
        while( true ) {
          ppiStack220 = (int **)&bStack105;
          ppiStack216 = (int **)0x1;
          puStack228 = (undefined *)0x157a9;
          ppiStack224 = ppiStack240;
          cVar6 = (*(code *)ppiStack236[0xb])();
          ppiVar26 = ppiStack76;
          ppiVar8 = ppiStack240;
          if (cVar6 != '\x01') break;
          if (bStack105 == 0) {
            *(undefined *)(ppiStack236 + 0xc) = 0;
            ppiStack236[10] = (int *)0x0;
            uVar14 = 1;
            ppiVar8 = ppiStack192;
            goto LAB_0001582a;
          }
          *(byte *)(ppiStack236 + 0xc) = bStack105;
          ppiStack236 = (int **)((int)ppiStack236 + 0x31);
          ppiStack216 = (int **)(uint)bStack105;
          ppiStack224 = ppiStack76;
          puStack228 = (undefined *)0x157d7;
          ppiStack220 = ppiStack236;
          bVar7 = (*(code *)ppiStack76[0xe][0xb])();
          ppiVar8 = ppiVar26;
          if (bVar7 != bStack105) break;
          ppiStack236 = (int **)ppiVar26[0xe];
          ppiStack240 = ppiVar26;
        }
LAB_000157dd:
        ppiVar8[0xc] = (int *)0x66;
        ppiStack240 = ppiVar8;
LAB_00015824:
        uVar14 = 0;
        ppiVar8 = ppiStack192;
      }
    }
  }
  else {
    ppiStack76[0xc] = (int *)0x6c;
    appuStack84[0] = apuStack36;
LAB_000150c5:
    uVar14 = 0;
  }
LAB_0001582a:
  ppuStack232 = ppuStack184;
  if (*ppiVar8 == piStack104) {
    return uVar14;
  }
  puStack228 = (undefined *)0x15852;
  func_0x00011af0();
  ppiStack288 = ppiStack220;
  ppuStack280 = &__DT_PLTGOT;
  ppiStack256 = (int **)&__stack_chk_guard;
  piStack248 = ___stack_chk_guard;
  piStack284 = ppiStack220[0xe];
  pbStack268 = &bStack249;
  ppiStack272 = ppiStack220;
  puStack264 = (uint *)0x1;
  puStack276 = (undefined *)0x158a4;
  puStack228 = (undefined *)appuStack84;
  cVar6 = (*(code *)piStack284[0xb])();
  if (cVar6 == '\x01') {
    if (bStack249 == 0) {
      *ppiStack216 = (int *)0x0;
      *(undefined *)(piStack284 + 0xc) = 0;
      piStack284[10] = 0;
      uVar14 = 1;
    }
    else {
      *ppiStack216 = piStack284 + 0xc;
      *(byte *)(piStack284 + 0xc) = bStack249;
      pbStack268 = (byte *)((int)*ppiStack216 + 1);
      puStack264 = (uint *)(uint)bStack249;
      ppiStack272 = ppiStack288;
      puStack276 = (undefined *)0x158d2;
      bVar7 = (*(code *)ppiStack288[0xe][0xb])();
      uVar14 = 1;
      if (bVar7 != bStack249) goto LAB_000158df;
    }
  }
  else {
LAB_000158df:
    ppiStack288[0xc] = (int *)0x66;
    uVar14 = 0;
  }
  if (*ppiStack256 == piStack248) {
    return uVar14;
  }
  puStack276 = (undefined *)0x15919;
  func_0x00011af0();
  pbVar5 = pbStack268;
  puStack308 = &LAB_00015931;
  piStack296 = ___stack_chk_guard;
  pbStack316 = (byte *)((int)&uStack300 + 2);
  ppuStack312 = (undefined **)0x1;
  ppiStack320 = (int **)pbStack268;
  uStack324 = 0x15958;
  puStack276 = (undefined *)&puStack228;
  cVar6 = (**(code **)(*(int *)(pbStack268 + 0x38) + 0x2c))();
  ppiVar8 = (int **)&__stack_chk_guard;
  if (cVar6 == '\x01') {
    *puStack264 = uStack300 >> 0x10 & 0xff;
    iVar12 = *(int *)(pbVar5 + 0x38);
    pbStack316 = (byte *)((int)&uStack300 + 3);
    ppuStack312 = (undefined **)0x1;
    ppiStack320 = (int **)pbVar5;
    uStack324 = 0x1597d;
    ppiStack304 = (int **)&__stack_chk_guard;
    cVar6 = (**(code **)(iVar12 + 0x2c))();
    ppiVar8 = ppiStack304;
    if (cVar6 == '\x01') {
      if (uStack300._3_1_ == 0) {
        *piStack260 = 0;
        uVar14 = 1;
      }
      else {
        *piStack260 = iVar12 + 0x30;
        *(byte *)(iVar12 + 0x30) = uStack300._3_1_;
        pbStack316 = (byte *)(*piStack260 + 1);
        ppuStack312 = (undefined **)(uint)uStack300._3_1_;
        ppiStack320 = (int **)pbVar5;
        uStack324 = 0x159b1;
        cVar6 = (**(code **)(*(int *)(pbVar5 + 0x38) + 0x2c))();
        uVar14 = 1;
        ppiVar8 = ppiStack304;
        if (cVar6 != uStack300._3_1_) goto LAB_000159c4;
      }
    }
    else {
      *(undefined4 *)(pbVar5 + 0x30) = 0x66;
      uVar14 = 0;
    }
  }
  else {
LAB_000159c4:
    *(undefined4 *)(pbVar5 + 0x30) = 0x66;
    uVar14 = 0;
  }
  if (*ppiVar8 == piStack296) {
    return uVar14;
  }
  puStack308 = (undefined *)0x159fd;
  func_0x00011af0();
  pbStack316 = pbVar5;
  piStack328 = ___stack_chk_guard;
  iVar12 = *(int *)(uStack300 + 0x38);
  pbStack348 = &bStack329;
  pbStack344 = (byte *)0x1;
  ppiStack320 = ppiVar8;
  ppuStack312 = &__DT_PLTGOT;
  puStack308 = (undefined *)&puStack276;
  cVar6 = (**(code **)(iVar12 + 0x2c))(uStack300);
  if (cVar6 == '\x01') {
    if (bStack329 == 0) {
      *piStack296 = 0;
      uVar14 = 1;
      goto LAB_00015a95;
    }
    *piStack296 = iVar12 + 0x30;
    *(byte *)(iVar12 + 0x30) = bStack329;
    pbStack348 = (byte *)(*piStack296 + 1);
    pbStack344 = (byte *)(uint)bStack329;
    bVar7 = (**(code **)(*(int *)(uStack300 + 0x38) + 0x2c))(uStack300);
    uVar14 = 1;
    if (bVar7 == bStack329) goto LAB_00015a95;
  }
  *(undefined4 *)(uStack300 + 0x30) = 0x66;
  uVar14 = 0;
LAB_00015a95:
  if (___stack_chk_guard != piStack328) {
    func_0x00011af0();
    uVar14 = 0;
    if (pbStack348 == (byte *)0x4) {
      *pbStack340 = *pbStack344 >> 2 & 7;
      *(uint *)(pbStack340 + 4) = (uint)*(ushort *)(pbStack344 + 1);
      uVar15 = 0xffffffff;
      if ((*pbStack344 & 1) != 0) {
        uVar15 = (uint)pbStack344[3];
      }
      *(uint *)(pbStack340 + 8) = uVar15;
      uVar14 = 1;
    }
    return uVar14;
  }
  return uVar14;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00014d20(uint param_1,char param_2)

{
  uint *puVar1;
  undefined8 uVar2;
  int iVar3;
  undefined4 *puVar4;
  byte *pbVar5;
  char cVar6;
  byte bVar7;
  int **ppiVar8;
  int *piVar9;
  undefined4 uVar10;
  int **ppiVar11;
  int **ppiVar12;
  int iVar13;
  int **ppiVar14;
  uint uVar15;
  uint uVar16;
  int *piVar17;
  undefined (*pauVar18) [16];
  uint uVar19;
  undefined (*pauVar20) [16];
  int *piVar21;
  int *piVar22;
  int **ppiVar23;
  int **ppiVar24;
  uint *puVar25;
  int **ppiVar26;
  bool bVar27;
  undefined auVar28 [16];
  undefined auVar29 [16];
  int *piVar30;
  int *piVar31;
  int *piVar32;
  undefined auVar33 [16];
  byte *pbStack316;
  byte *pbStack312;
  byte *pbStack308;
  byte bStack297;
  int *piStack296;
  undefined4 uStack292;
  int **ppiStack288;
  byte *pbStack284;
  undefined **ppuStack280;
  undefined *puStack276;
  int **ppiStack272;
  undefined4 uStack268;
  int *piStack264;
  int **ppiStack256;
  int *piStack252;
  undefined **ppuStack248;
  undefined *puStack244;
  int **ppiStack240;
  byte *pbStack236;
  uint *puStack232;
  int *piStack228;
  int **ppiStack224;
  byte bStack217;
  int *piStack216;
  int **ppiStack208;
  int **ppiStack204;
  undefined **ppuStack200;
  undefined *puStack196;
  int **ppiStack192;
  int **ppiStack188;
  int **ppiStack184;
  int **ppiStack176;
  int **ppiStack172;
  int **ppiStack168;
  int **ppiStack164;
  int **ppiStack160;
  int **ppiStack156;
  undefined **ppuStack152;
  int **ppiStack148;
  int **ppiStack144;
  int **ppiStack140;
  int **ppiStack136;
  int iStack132;
  int **ppiStack128;
  int **ppiStack124;
  int iStack120;
  int **ppiStack116;
  undefined auStack112 [16];
  int *piStack96;
  int *piStack92;
  int *piStack88;
  int *piStack84;
  byte bStack73;
  int *piStack72;
  undefined4 uStack68;
  uint uStack64;
  uint *puStack60;
  undefined **ppuStack56;
  undefined *apuStack52 [2];
  int **ppiStack44;
  int **ppiStack40;
  int **ppiStack36;
  byte bStack30;
  byte bStack29;
  undefined uStack28;
  undefined uStack27;
  ushort uStack26;
  int *piStack24;
  
  apuStack52[0] = &LAB_00014d31;
  ppiStack44 = (int **)&__stack_chk_guard;
  piStack24 = ___stack_chk_guard;
  ppiStack36 = *(int ***)(param_1 + 0x38);
  puVar25 = (uint *)&uStack26;
  ppuStack56 = (undefined **)0x2;
  uStack64 = param_1;
  uStack68 = 0x14d60;
  puStack60 = puVar25;
  cVar6 = (*(code *)ppiStack36[0xb])();
  if (cVar6 == '\x02') {
    *(uint *)(param_1 + 0x14) = (uint)uStack26;
    ppuStack56 = (undefined **)0x2;
    uStack64 = param_1;
    uStack68 = 0x14d8a;
    puStack60 = puVar25;
    cVar6 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
    if (cVar6 != '\x02') goto LAB_00014f05;
    *(uint *)(param_1 + 0x18) = (uint)uStack26;
    ppuStack56 = (undefined **)0x2;
    uStack64 = param_1;
    uStack68 = 0x14db4;
    puStack60 = puVar25;
    cVar6 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
    if (cVar6 != '\x02') goto LAB_00014f05;
    *(uint *)(param_1 + 0x1c) = (uint)uStack26;
    ppuStack56 = (undefined **)0x2;
    uStack64 = param_1;
    uStack68 = 0x14dde;
    puStack60 = puVar25;
    cVar6 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
    if (cVar6 != '\x02') goto LAB_00014f05;
    *(uint *)(param_1 + 0x20) = (uint)uStack26;
    puStack60 = (uint *)&bStack29;
    ppuStack56 = (undefined **)0x1;
    uStack64 = param_1;
    uStack68 = 0x14e0c;
    cVar6 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
    if (cVar6 != '\x01') {
      *(undefined4 *)(param_1 + 0x30) = 0x66;
      uStack64 = *(uint *)(param_1 + 0x28);
      uStack68 = 0x14f38;
      FUN_00015c20();
LAB_00014f3b:
      *(undefined4 *)(param_1 + 0x28) = 0;
      goto LAB_00014f0c;
    }
    *(byte *)(param_1 + 0x24) = bStack29 >> 6 & 1;
    uStack64 = *(int *)(param_1 + 0x28);
    ppiStack40._0_1_ = bStack29;
    if (uStack64 != 0) {
      ppiStack40 = (int **)((uint)ppiStack40 & 0xffffff00 | (uint)bStack29);
      uStack68 = 0x14e3b;
      FUN_00015c20();
      *(undefined4 *)(param_1 + 0x28) = 0;
    }
    if ((char)bStack29 < '\0') {
      uStack64 = (uint)(byte)(((byte)ppiStack40 & 7) + 1);
      puStack60 = (uint *)0x0;
      uStack68 = 0x14f5f;
      piVar9 = (int *)FUN_00015b90();
      *(int **)(param_1 + 0x28) = piVar9;
      if (piVar9 != (int *)0x0) {
        if (*piVar9 != 0) {
          ppiVar8 = (int **)0x0;
          puVar25 = (uint *)0x2;
          do {
            ppuStack56 = (undefined **)0x3;
            puStack60 = (uint *)&bStack29;
            uStack64 = param_1;
            uStack68 = 0x14f8e;
            ppiStack40 = ppiVar8;
            cVar6 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
            if (cVar6 != '\x03') {
              uStack64 = *(uint *)(param_1 + 0x28);
              uStack68 = 0x15055;
              FUN_00015c20();
              *(undefined4 *)(param_1 + 0x30) = 0x66;
              goto LAB_00014f3b;
            }
            puVar4 = *(undefined4 **)(param_1 + 0x28);
            iVar13 = puVar4[2];
            *(byte *)(iVar13 + -2 + (int)puVar25) = bStack29;
            *(undefined *)(iVar13 + -1 + (int)puVar25) = uStack28;
            *(undefined *)(iVar13 + (int)puVar25) = uStack27;
            ppiVar8 = (int **)((int)ppiStack40 + 1);
            puVar25 = (uint *)((int)puVar25 + 3);
          } while (ppiVar8 < (int **)*puVar4);
        }
        goto LAB_00014e55;
      }
LAB_00014fca:
      *(undefined4 *)(param_1 + 0x30) = 0x6d;
      goto LAB_00014f0c;
    }
LAB_00014e55:
    if (param_2 != '\0') {
      puStack60 = (uint *)(*(int *)(param_1 + 0x10) + 1);
      ppuStack56 = (undefined **)0x18;
      uStack64 = *(uint *)(param_1 + 0x2c);
      uStack68 = 0x14e6e;
      ppiVar8 = (int **)FUN_00015cf0();
      if (ppiVar8 == (int **)0x0) goto LAB_00014fca;
      *(int ***)(param_1 + 0x2c) = ppiVar8;
      iVar13 = *(int *)(param_1 + 0x10);
      puVar25 = (uint *)(iVar13 * 3);
      *(undefined8 *)(ppiVar8 + iVar13 * 6 + 4) = *(undefined8 *)(param_1 + 0x24);
      uVar2 = *(undefined8 *)(param_1 + 0x14);
      *(undefined8 *)(ppiVar8 + iVar13 * 6 + 2) = *(undefined8 *)(param_1 + 0x1c);
      *(undefined8 *)(ppiVar8 + iVar13 * 6) = uVar2;
      iVar3 = *(int *)(param_1 + 0x28);
      if (iVar3 != 0) {
        uStack64 = (uint)*(byte *)(iVar3 + 4);
        puStack60 = *(uint **)(iVar3 + 8);
        uStack68 = 0x14ebf;
        ppiStack40 = ppiVar8;
        piVar9 = (int *)FUN_00015b90();
        ppiStack40[iVar13 * 6 + 5] = piVar9;
        if (piVar9 == (int *)0x0) goto LAB_00014fca;
      }
      *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + 1;
    }
    ppiStack36[10] = (int *)(*(int *)(param_1 + 0x20) * *(int *)(param_1 + 0x1c));
    puVar25 = *(uint **)(param_1 + 0x38);
    puStack60 = (uint *)&bStack30;
    ppuStack56 = (undefined **)0x1;
    uStack64 = param_1;
    uStack68 = 0x14ef4;
    (*(code *)puVar25[0xb])();
    uVar15 = (uint)bStack30;
    if (8 < uVar15) goto LAB_00014f05;
    *(undefined *)(puVar25 + 0xc) = 0;
    *puVar25 = uVar15;
    uVar16 = 1 << (bStack30 & 0x1f);
    puVar25[1] = uVar16;
    puVar25[2] = uVar16 + 1;
    uVar10 = 1;
    puVar25[3] = uVar16 + 2;
    puVar25[4] = uVar15 + 1;
    puVar25[5] = 2 << (bStack30 & 0x1f);
    *(undefined (*) [16])(puVar25 + 6) = ZEXT416(0x1002);
    iVar13 = -0x1000;
    do {
      puVar1 = puVar25 + iVar13 + 0x184c;
      *puVar1 = 0x1002;
      puVar1[1] = 0x1002;
      puVar1[2] = 0x1002;
      puVar1[3] = 0x1002;
      puVar1 = puVar25 + iVar13 + 0x1850;
      *puVar1 = 0x1002;
      puVar1[1] = 0x1002;
      puVar1[2] = 0x1002;
      puVar1[3] = 0x1002;
      iVar13 = iVar13 + 8;
    } while (iVar13 != 0);
  }
  else {
LAB_00014f05:
    *(undefined4 *)(param_1 + 0x30) = 0x66;
LAB_00014f0c:
    uVar10 = 0;
  }
  if (*ppiStack44 == piStack24) {
    return uVar10;
  }
  apuStack52[0] = (undefined *)0x15069;
  func_0x00011af0();
  uStack64 = param_1;
  ppuStack152 = &__DT_PLTGOT;
  piStack72 = ___stack_chk_guard;
  ppiStack204 = (int **)ppiStack44[0xe];
  ppiStack172 = ppiStack36;
  if (ppiStack36 == (int **)0x0) {
    ppiStack172 = (int **)ppiStack44[7];
  }
  piVar9 = ppiStack204[10];
  ppiStack204[10] = (int *)((int)piVar9 - (int)ppiStack172);
  auVar33 = _UNK_00017f30;
  ppiStack208 = ppiStack172;
  ppiVar8 = (int **)&__stack_chk_guard;
  puStack60 = puVar25;
  ppuStack56 = &__DT_PLTGOT;
  if ((int *)((int)piVar9 - (int)ppiStack172) < (int *)0xffff0001) {
    ppiVar26 = (int **)ppiStack204[7];
    uVar10 = 0;
    apuStack52[0] = &stack0xfffffffc;
    if ((int)ppiVar26 < 0x1000) {
      ppiStack140 = (int **)ppiStack204[1];
      ppiStack116 = (int **)ppiStack204[2];
      ppiVar12 = (int **)ppiStack204[6];
      if (ppiVar26 == (int **)0x0) {
        ppiVar8 = (int **)0x0;
        ppiStack164 = (int **)0x0;
      }
      else if (ppiStack172 == (int **)0x0) {
        ppiVar8 = (int **)0x0;
        ppiStack164 = ppiVar26;
      }
      else {
        uVar19 = -(int)ppiStack172;
        uVar16 = -(int)ppiVar26;
        uVar15 = uVar16;
        if (uVar16 <= uVar19 && ppiVar26 != ppiStack172) {
          uVar15 = uVar19;
        }
        ppiVar11 = (int **)-uVar15;
        ppiVar8 = (int **)0x0;
        if ((int **)0x1f < ppiVar11) {
          if (uVar16 <= uVar19 && ppiVar26 != ppiStack172) {
            uVar16 = uVar19;
          }
          if (((int **)((int)(ppiStack204 + 0x4c) + (int)ppiVar26) <= ppiStack40) ||
             ((int)ppiStack40 - uVar16 <= (int)ppiStack204 + (int)ppiVar26 + uVar16 + 0x130)) {
            ppiVar8 = (int **)((uint)ppiVar11 & 0xffffffe0);
            pauVar18 = (undefined (*) [16])(ppiStack40 + 4);
            pauVar20 = (undefined (*) [16])((int)(ppiStack204 + 0x48) + (int)ppiVar26);
            ppiVar26 = (int **)((int)ppiVar26 - (int)ppiVar8);
            ppiStack208 = ppiVar8;
            do {
              auVar29 = pshufb(*pauVar20,auVar33);
              auVar28 = pshufb(pauVar20[-1],auVar33);
              pauVar18[-1] = auVar29;
              *pauVar18 = auVar28;
              pauVar18 = pauVar18[2];
              pauVar20 = pauVar20[-2];
              ppiStack208 = ppiStack208 + -8;
            } while (ppiStack208 != (int **)0x0);
            ppiStack164 = ppiVar26;
            ppiStack176 = ppiStack204;
            if (ppiVar8 == ppiVar11) goto LAB_00015209;
          }
        }
        do {
          *(undefined *)((int)ppiStack40 + (int)ppiVar8) =
               *(undefined *)((int)ppiStack204 + 0x12f + (int)ppiVar26);
          ppiStack164 = (int **)((int)ppiVar26 + -1);
          ppiVar8 = (int **)((int)ppiVar8 + 1);
          ppiStack208 = ppiStack40;
          ppiStack176 = ppiStack204;
          if (ppiStack172 <= ppiVar8) break;
          bVar27 = ppiVar26 != (int **)0x1;
          ppiVar26 = ppiStack164;
        } while (bVar27);
      }
LAB_00015209:
      ppiStack160 = (int **)&__stack_chk_guard;
      apuStack52[0] = &stack0xfffffffc;
      if (ppiVar8 < ppiStack172) {
        iStack132 = (int)ppiStack204 + 0x131;
        ppiStack124 = ppiStack40 + 4;
        iStack120 = (int)ppiStack204 + 0x121;
        piVar9 = (int *)0x1002;
        piVar30 = (int *)0x1002;
        piVar31 = (int *)0x1002;
        piVar32 = (int *)0x1002;
        auStack112 = _UNK_00017f30;
        auVar33 = _UNK_00017f30;
        ppiStack176 = ppiStack204;
        ppiStack148 = ppiVar12;
        piStack96 = piVar9;
        piStack92 = piVar30;
        piStack88 = piVar31;
        piStack84 = piVar32;
        apuStack52[0] = &stack0xfffffffc;
        do {
          ppiStack204 = (int **)ppiStack44[0xe];
          piVar21 = ppiStack204[4];
          if ((int *)0xc < piVar21) {
            ppiStack44[0xc] = (int *)0x70;
            ppiStack208 = ppiStack44;
            goto LAB_00015824;
          }
          piVar17 = ppiStack204[8];
          ppiStack168 = ppiVar8;
          if (piVar17 < piVar21) {
            ppiStack156 = ppiStack204 + 0xc;
            ppiStack144 = (int **)((int)ppiStack204 + 0x31);
            cVar6 = *(char *)(ppiStack204 + 0xc);
            do {
              ppiStack208 = ppiStack156;
              if (cVar6 == '\0') {
                ppiStack188 = ppiStack156;
                ppiStack192 = ppiStack44;
                ppiStack184 = (int **)0x1;
                puStack196 = (undefined *)0x152d2;
                cVar6 = (*(code *)ppiStack44[0xe][0xb])();
                ppiVar8 = ppiStack44;
                if (cVar6 != '\x01') {
                  ppiStack44[0xc] = (int *)0x66;
                  goto LAB_00015824;
                }
                if (*(byte *)ppiStack208 == 0) goto LAB_000157e6;
                ppiStack184 = (int **)(uint)*(byte *)ppiStack208;
                ppiStack188 = ppiStack144;
                ppiStack192 = ppiStack44;
                puStack196 = (undefined *)0x15300;
                uVar15 = (*(code *)ppiStack44[0xe][0xb])();
                if ((char)uVar15 != *(char *)ppiStack156) goto LAB_000157dd;
                bVar7 = *(byte *)((int)ppiStack204 + 0x31);
                *(undefined *)((int)ppiStack204 + 0x31) = 2;
                piVar21 = ppiStack204[4];
                piVar17 = ppiStack204[8];
                auVar33 = auStack112;
                piVar9 = piStack96;
                piVar30 = piStack92;
                piVar31 = piStack88;
                piVar32 = piStack84;
              }
              else {
                bVar7 = *(byte *)((int)ppiStack204 + 0x31);
                uVar15 = (uint)CONCAT11(bVar7 + 1,cVar6);
                *(char *)((int)ppiStack204 + 0x31) = (char)(uVar15 >> 8);
                bVar7 = *(byte *)((int)ppiStack204 + bVar7 + 0x30);
              }
              cVar6 = (char)uVar15 + -1;
              *(char *)(ppiStack204 + 0xc) = cVar6;
              piVar22 = (int *)((uint)bVar7 << ((byte)piVar17 & 0x1f) | (uint)ppiStack204[9]);
              ppiStack204[9] = piVar22;
              piVar17 = piVar17 + 2;
              ppiStack204[8] = piVar17;
            } while (piVar17 < piVar21);
          }
          else {
            piVar22 = ppiStack204[9];
          }
          ppiVar12 = (int **)((uint)*(ushort *)((int)ppuStack152 + (int)piVar21 * 2 + -0x2fe4) &
                             (uint)piVar22);
          ppiStack204[9] = (int *)((uint)piVar22 >> ((byte)piVar21 & 0x1f));
          ppiStack204[8] = (int *)((int)piVar17 - (int)piVar21);
          if (ppiStack204[3] < (int *)0x1001) {
            piVar17 = (int *)((int)ppiStack204[3] + 1);
            ppiStack204[3] = piVar17;
            if ((piVar21 < (int *)0xc) && (ppiStack204[5] < piVar17)) {
              ppiStack204[5] = (int *)((int)ppiStack204[5] * 2);
              ppiStack204[4] = (int *)((int)piVar21 + 1);
            }
          }
          ppiStack208 = ppiStack44;
          if (ppiVar12 == ppiStack116) {
            ppiStack44[0xc] = (int *)0x71;
            goto LAB_00015824;
          }
          if (ppiVar12 == ppiStack140) {
            iVar13 = -0x1000;
            do {
              ppiVar8 = ppiStack176 + iVar13 + 0x184c;
              *ppiVar8 = piVar9;
              ppiVar8[1] = piVar30;
              ppiVar8[2] = piVar31;
              ppiVar8[3] = piVar32;
              ppiVar8 = ppiStack176 + iVar13 + 0x1850;
              *ppiVar8 = piVar9;
              ppiVar8[1] = piVar30;
              ppiVar8[2] = piVar31;
              ppiVar8[3] = piVar32;
              iVar13 = iVar13 + 8;
            } while (iVar13 != 0);
            ppiStack176[3] = (int *)((int)ppiStack176[2] + 1);
            ppiStack176[4] = (int *)((int)*ppiStack176 + 1);
            ppiStack176[5] = (int *)(1 << ((byte)(int *)((int)*ppiStack176 + 1) & 0x1f));
            ppiStack176[6] = (int *)0x1002;
            ppiVar12 = (int **)0x1002;
          }
          else {
            ppiStack156 = ppiVar12;
            if ((int)ppiStack140 <= (int)ppiVar12) {
              ppiVar8 = ppiVar12;
              ppiVar26 = ppiStack164;
              if (ppiStack176[(int)(ppiVar12 + 0x213)] == (int *)0x1002) {
                if (ppiVar12 != (int **)((int)ppiStack176[3] + -2)) {
                  ppiStack44[0xc] = (int *)0x70;
                  ppiVar8 = ppiStack160;
                  goto LAB_000150c5;
                }
                ppiVar8 = ppiStack148;
                if ((int)ppiStack140 < (int)ppiStack148) {
                  iVar13 = 1;
                  while ((int)ppiVar8 < 0x1000) {
                    ppiVar8 = (int **)ppiStack176[(int)(ppiVar8 + 0x213)];
                    if ((0xfff < iVar13) ||
                       (iVar13 = iVar13 + (uint)((int)ppiStack140 < (int)ppiVar8),
                       (int)ppiVar8 <= (int)ppiStack140)) goto LAB_0001556c;
                  }
                  ppiVar8 = (int **)0x1002;
                }
LAB_0001556c:
                *(char *)((int)(ppiStack176 + 0x4c) + (int)ppiStack164) = (char)ppiVar8;
                *(char *)((int)ppiStack176 + 0x112d + (int)ppiStack176[3]) = (char)ppiVar8;
                ppiStack204 = ppiStack148;
                ppiVar8 = ppiStack148;
                ppiVar26 = (int **)((int)ppiStack164 + 1);
                ppiStack208 = ppiStack176;
              }
              if ((int)ppiVar26 < 0xfff) {
                pauVar18 = (undefined (*) [16])(iStack120 + (int)ppiVar26);
                ppiStack204 = (int **)~(uint)ppiVar26;
                while (((int)ppiStack140 < (int)ppiVar8 && ((int)ppiVar8 < 0x1000))) {
                  *(undefined *)((int)(ppiStack176 + 0x4c) + (int)ppiVar26) =
                       *(undefined *)((int)ppiStack176 + 0x112f + (int)ppiVar8);
                  ppiVar8 = (int **)ppiStack176[(int)(ppiVar8 + 0x213)];
                  pauVar18 = (undefined (*) [16])(*pauVar18 + 1);
                  ppiStack204 = (int **)((int)ppiStack204 + -1);
                  bVar27 = 0xffd < (int)ppiVar26;
                  ppiVar26 = (int **)((int)ppiVar26 + 1);
                  ppiStack208 = ppiStack176;
                  if (bVar27) goto LAB_000157e6;
                }
                if ((int)ppiVar8 < 0x1000) {
                  ppiVar11 = (int **)((int)ppiVar26 + 1);
                  *(char *)((int)(ppiStack176 + 0x4c) + (int)ppiVar26) = (char)ppiVar8;
                  ppiVar8 = (int **)((int)ppiStack168 - (int)ppiStack172);
                  ppiStack164 = ppiVar11;
                  if ((ppiStack168 < ppiStack172) && (ppiVar11 != (int **)0x0)) {
                    ppiVar23 = (int **)~(uint)ppiVar26;
                    ppiVar14 = ppiVar23;
                    if (ppiVar23 < ppiVar8) {
                      ppiVar14 = ppiVar8;
                    }
                    ppiVar14 = (int **)-(int)ppiVar14;
                    if ((int **)0x1f < ppiVar14) {
                      ppiStack144 = (int **)((int)ppiStack40 + (int)ppiStack168);
                      ppiVar24 = ppiVar23;
                      if (ppiVar23 < ppiVar8) {
                        ppiVar24 = ppiVar8;
                      }
                      ppiStack136 = ppiVar14;
                      ppiStack128 = ppiVar23;
                      if (((int **)(iStack132 + (int)ppiVar26) <= ppiStack144) ||
                         ((uint)(((int)ppiStack168 - (int)ppiVar24) + (int)ppiStack40) <=
                          (uint)((int)ppiVar26 + (int)ppiVar24 + iStack132))) {
                        ppiStack144 = (int **)((uint)ppiVar14 & 0xffffffe0);
                        ppiVar11 = (int **)((int)ppiVar11 - (int)ppiStack144);
                        pauVar20 = (undefined (*) [16])((int)ppiStack124 + (int)ppiStack168);
                        ppiStack168 = (int **)((int)ppiStack168 + (int)ppiStack144);
                        if (ppiVar8 < ppiStack204) {
                          ppiVar8 = ppiStack204;
                        }
                        uVar15 = -(int)ppiVar8 & 0xffffffe0;
                        do {
                          auVar29 = pshufb(*pauVar18,auVar33);
                          auVar28 = pshufb(pauVar18[-1],auVar33);
                          pauVar20[-1] = auVar29;
                          *pauVar20 = auVar28;
                          pauVar20 = pauVar20[2];
                          pauVar18 = pauVar18[-2];
                          uVar15 = uVar15 - 0x20;
                        } while (uVar15 != 0);
                        ppiStack164 = ppiVar11;
                        if (ppiStack144 == ppiVar14) goto LAB_00015416;
                      }
                    }
                    do {
                      *(undefined *)((int)ppiStack40 + (int)ppiStack168) =
                           *(undefined *)((int)ppiStack176 + 0x12f + (int)ppiVar11);
                      ppiStack164 = (int **)((int)ppiVar11 + -1);
                      ppiStack168 = (int **)((int)ppiStack168 + 1);
                      if (ppiStack172 <= ppiStack168) break;
                      bVar27 = ppiVar11 != (int **)0x1;
                      ppiVar11 = ppiStack164;
                    } while (bVar27);
                  }
                  goto LAB_00015416;
                }
              }
LAB_000157e6:
              ppiStack44[0xc] = (int *)0x70;
              goto LAB_00015824;
            }
            *(char *)((int)ppiStack40 + (int)ppiStack168) = (char)ppiVar12;
            ppiStack168 = (int **)((int)ppiStack168 + 1);
LAB_00015416:
            if ((ppiStack148 != (int **)0x1002) &&
               (ppiStack176[(int)ppiStack176[3] + 0x84a] == (int *)0x1002)) {
              ppiStack176[(int)ppiStack176[3] + 0x84a] = (int *)ppiStack148;
              if (ppiVar12 != (int **)((int)ppiStack176[3] + -2)) {
                ppiStack148 = ppiVar12;
              }
              if ((int)ppiStack140 < (int)ppiStack148) {
                iVar13 = 1;
                while ((int)ppiStack148 < 0x1000) {
                  ppiStack148 = (int **)ppiStack176[(int)(ppiStack148 + 0x213)];
                  if ((0xfff < iVar13) ||
                     (iVar13 = iVar13 + (uint)((int)ppiStack140 < (int)ppiStack148),
                     (int)ppiStack148 <= (int)ppiStack140)) goto LAB_0001572a;
                }
                ppiStack148 = (int **)0x1002;
              }
LAB_0001572a:
              *(char *)((int)ppiStack176 + 0x112f + (int)(int **)((int)ppiStack176[3] + -2)) =
                   (char)ppiStack148;
            }
          }
          ppiVar8 = ppiStack168;
          ppiStack208 = ppiStack44;
          ppiStack204 = ppiStack176;
          ppiStack148 = ppiVar12;
        } while (ppiStack168 < ppiStack172);
      }
      ppiStack204[6] = (int *)ppiVar12;
      ppiStack204[7] = (int *)ppiStack164;
      uVar10 = 1;
      ppiVar8 = ppiStack160;
      ppiStack148 = ppiVar12;
      if (ppiStack204[10] == (int *)0x0) {
        ppiStack204 = (int **)ppiStack44[0xe];
        ppiStack208 = ppiStack44;
        while( true ) {
          ppiStack188 = (int **)&bStack73;
          ppiStack184 = (int **)0x1;
          puStack196 = (undefined *)0x157a9;
          ppiStack192 = ppiStack208;
          cVar6 = (*(code *)ppiStack204[0xb])();
          ppiVar26 = ppiStack44;
          ppiVar8 = ppiStack208;
          if (cVar6 != '\x01') break;
          if (bStack73 == 0) {
            *(undefined *)(ppiStack204 + 0xc) = 0;
            ppiStack204[10] = (int *)0x0;
            uVar10 = 1;
            ppiVar8 = ppiStack160;
            goto LAB_0001582a;
          }
          *(byte *)(ppiStack204 + 0xc) = bStack73;
          ppiStack204 = (int **)((int)ppiStack204 + 0x31);
          ppiStack184 = (int **)(uint)bStack73;
          ppiStack192 = ppiStack44;
          puStack196 = (undefined *)0x157d7;
          ppiStack188 = ppiStack204;
          bVar7 = (*(code *)ppiStack44[0xe][0xb])();
          ppiVar8 = ppiVar26;
          if (bVar7 != bStack73) break;
          ppiStack204 = (int **)ppiVar26[0xe];
          ppiStack208 = ppiVar26;
        }
LAB_000157dd:
        ppiVar8[0xc] = (int *)0x66;
        ppiStack208 = ppiVar8;
LAB_00015824:
        uVar10 = 0;
        ppiVar8 = ppiStack160;
      }
    }
  }
  else {
    ppiStack44[0xc] = (int *)0x6c;
    apuStack52[0] = &stack0xfffffffc;
LAB_000150c5:
    uVar10 = 0;
  }
LAB_0001582a:
  ppuStack200 = ppuStack152;
  if (*ppiVar8 == piStack72) {
    return uVar10;
  }
  puStack196 = (undefined *)0x15852;
  func_0x00011af0();
  ppiStack256 = ppiStack188;
  ppuStack248 = &__DT_PLTGOT;
  ppiStack224 = (int **)&__stack_chk_guard;
  piStack216 = ___stack_chk_guard;
  piStack252 = ppiStack188[0xe];
  pbStack236 = &bStack217;
  ppiStack240 = ppiStack188;
  puStack232 = (uint *)0x1;
  puStack244 = (undefined *)0x158a4;
  puStack196 = (undefined *)apuStack52;
  cVar6 = (*(code *)piStack252[0xb])();
  if (cVar6 == '\x01') {
    if (bStack217 == 0) {
      *ppiStack184 = (int *)0x0;
      *(undefined *)(piStack252 + 0xc) = 0;
      piStack252[10] = 0;
      uVar10 = 1;
    }
    else {
      *ppiStack184 = piStack252 + 0xc;
      *(byte *)(piStack252 + 0xc) = bStack217;
      pbStack236 = (byte *)((int)*ppiStack184 + 1);
      puStack232 = (uint *)(uint)bStack217;
      ppiStack240 = ppiStack256;
      puStack244 = (undefined *)0x158d2;
      bVar7 = (*(code *)ppiStack256[0xe][0xb])();
      uVar10 = 1;
      if (bVar7 != bStack217) goto LAB_000158df;
    }
  }
  else {
LAB_000158df:
    ppiStack256[0xc] = (int *)0x66;
    uVar10 = 0;
  }
  if (*ppiStack224 == piStack216) {
    return uVar10;
  }
  puStack244 = (undefined *)0x15919;
  func_0x00011af0();
  pbVar5 = pbStack236;
  puStack276 = &LAB_00015931;
  piStack264 = ___stack_chk_guard;
  pbStack284 = (byte *)((int)&uStack268 + 2);
  ppuStack280 = (undefined **)0x1;
  ppiStack288 = (int **)pbStack236;
  uStack292 = 0x15958;
  puStack244 = (undefined *)&puStack196;
  cVar6 = (**(code **)(*(int *)(pbStack236 + 0x38) + 0x2c))();
  ppiVar8 = (int **)&__stack_chk_guard;
  if (cVar6 == '\x01') {
    *puStack232 = uStack268 >> 0x10 & 0xff;
    iVar13 = *(int *)(pbVar5 + 0x38);
    pbStack284 = (byte *)((int)&uStack268 + 3);
    ppuStack280 = (undefined **)0x1;
    ppiStack288 = (int **)pbVar5;
    uStack292 = 0x1597d;
    ppiStack272 = (int **)&__stack_chk_guard;
    cVar6 = (**(code **)(iVar13 + 0x2c))();
    ppiVar8 = ppiStack272;
    if (cVar6 == '\x01') {
      if (uStack268._3_1_ == 0) {
        *piStack228 = 0;
        uVar10 = 1;
      }
      else {
        *piStack228 = iVar13 + 0x30;
        *(byte *)(iVar13 + 0x30) = uStack268._3_1_;
        pbStack284 = (byte *)(*piStack228 + 1);
        ppuStack280 = (undefined **)(uint)uStack268._3_1_;
        ppiStack288 = (int **)pbVar5;
        uStack292 = 0x159b1;
        cVar6 = (**(code **)(*(int *)(pbVar5 + 0x38) + 0x2c))();
        uVar10 = 1;
        ppiVar8 = ppiStack272;
        if (cVar6 != uStack268._3_1_) goto LAB_000159c4;
      }
    }
    else {
      *(undefined4 *)(pbVar5 + 0x30) = 0x66;
      uVar10 = 0;
    }
  }
  else {
LAB_000159c4:
    *(undefined4 *)(pbVar5 + 0x30) = 0x66;
    uVar10 = 0;
  }
  if (*ppiVar8 == piStack264) {
    return uVar10;
  }
  puStack276 = (undefined *)0x159fd;
  func_0x00011af0();
  pbStack284 = pbVar5;
  piStack296 = ___stack_chk_guard;
  iVar13 = *(int *)(uStack268 + 0x38);
  pbStack316 = &bStack297;
  pbStack312 = (byte *)0x1;
  ppiStack288 = ppiVar8;
  ppuStack280 = &__DT_PLTGOT;
  puStack276 = (undefined *)&puStack244;
  cVar6 = (**(code **)(iVar13 + 0x2c))(uStack268);
  if (cVar6 == '\x01') {
    if (bStack297 == 0) {
      *piStack264 = 0;
      uVar10 = 1;
      goto LAB_00015a95;
    }
    *piStack264 = iVar13 + 0x30;
    *(byte *)(iVar13 + 0x30) = bStack297;
    pbStack316 = (byte *)(*piStack264 + 1);
    pbStack312 = (byte *)(uint)bStack297;
    bVar7 = (**(code **)(*(int *)(uStack268 + 0x38) + 0x2c))(uStack268);
    uVar10 = 1;
    if (bVar7 == bStack297) goto LAB_00015a95;
  }
  *(undefined4 *)(uStack268 + 0x30) = 0x66;
  uVar10 = 0;
LAB_00015a95:
  if (___stack_chk_guard != piStack296) {
    func_0x00011af0();
    uVar10 = 0;
    if (pbStack316 == (byte *)0x4) {
      *pbStack308 = *pbStack312 >> 2 & 7;
      *(uint *)(pbStack308 + 4) = (uint)*(ushort *)(pbStack312 + 1);
      uVar15 = 0xffffffff;
      if ((*pbStack312 & 1) != 0) {
        uVar15 = (uint)pbStack312[3];
      }
      *(uint *)(pbStack308 + 8) = uVar15;
      uVar10 = 1;
    }
    return uVar10;
  }
  return uVar10;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00015070(int *param_1,int *param_2,int *param_3)

{
  byte *pbVar1;
  char cVar2;
  byte bVar3;
  undefined4 uVar4;
  int *piVar5;
  int *piVar6;
  int iVar7;
  int *piVar8;
  byte bVar9;
  uint uVar10;
  int *piVar11;
  undefined (*pauVar12) [16];
  uint uVar13;
  undefined (*pauVar14) [16];
  uint uVar15;
  int **ppiVar16;
  int *piVar17;
  int *piVar18;
  int *piVar19;
  bool bVar20;
  undefined auVar21 [16];
  undefined auVar22 [16];
  int iVar23;
  int iVar24;
  int iVar25;
  int iVar26;
  undefined auVar27 [16];
  byte *pbStack268;
  byte *pbStack264;
  byte *pbStack260;
  byte bStack249;
  int *piStack248;
  undefined4 uStack244;
  int **ppiStack240;
  byte *pbStack236;
  undefined **ppuStack232;
  undefined *puStack228;
  int **ppiStack224;
  undefined4 uStack220;
  int *piStack216;
  int *piStack208;
  int iStack204;
  undefined **ppuStack200;
  undefined *puStack196;
  int *piStack192;
  byte *pbStack188;
  uint *puStack184;
  int *piStack180;
  int **ppiStack176;
  byte bStack169;
  int *piStack168;
  int *piStack160;
  int *piStack156;
  undefined **ppuStack152;
  undefined *puStack148;
  int *piStack144;
  int *piStack140;
  int *piStack136;
  int *piStack128;
  int *piStack124;
  int *piStack120;
  int *piStack116;
  int **ppiStack112;
  int *piStack108;
  undefined **ppuStack104;
  int *piStack100;
  int *piStack96;
  int *piStack92;
  int *piStack88;
  byte *pbStack84;
  int *piStack80;
  int *piStack76;
  byte *pbStack72;
  int *piStack68;
  undefined auStack64 [16];
  int iStack48;
  int iStack44;
  int iStack40;
  int iStack36;
  byte bStack25;
  int *piStack24;
  
  ppuStack104 = &__DT_PLTGOT;
  piStack24 = ___stack_chk_guard;
  piStack156 = (int *)param_1[0xe];
  if (param_3 == (int *)0x0) {
    param_3 = (int *)param_1[7];
  }
  iVar23 = piStack156[10];
  piStack156[10] = iVar23 - (int)param_3;
  auVar27 = _UNK_00017f30;
  ppiVar16 = (int **)&__stack_chk_guard;
  piStack124 = param_3;
  if ((uint)(iVar23 - (int)param_3) < 0xffff0001) {
    piVar11 = (int *)piStack156[7];
    uVar4 = 0;
    piStack160 = param_3;
    if ((int)piVar11 < 0x1000) {
      piStack92 = (int *)piStack156[1];
      piStack68 = (int *)piStack156[2];
      piVar6 = (int *)piStack156[6];
      if (piVar11 == (int *)0x0) {
        piVar17 = (int *)0x0;
        piStack116 = (int *)0x0;
      }
      else if (param_3 == (int *)0x0) {
        piVar17 = (int *)0x0;
        piStack116 = piVar11;
      }
      else {
        uVar13 = -(int)param_3;
        uVar10 = -(int)piVar11;
        uVar15 = uVar10;
        if (uVar10 <= uVar13 && piVar11 != param_3) {
          uVar15 = uVar13;
        }
        piVar5 = (int *)-uVar15;
        piVar17 = (int *)0x0;
        if ((int *)0x1f < piVar5) {
          if (uVar10 <= uVar13 && piVar11 != param_3) {
            uVar10 = uVar13;
          }
          if (((int *)((int)(piStack156 + 0x4c) + (int)piVar11) <= param_2) ||
             ((byte *)((int)param_2 - uVar10) <=
              (byte *)((int)(piStack156 + 0x4c) + (int)(uVar10 + (int)piVar11)))) {
            piVar17 = (int *)((uint)piVar5 & 0xffffffe0);
            pauVar12 = (undefined (*) [16])(param_2 + 4);
            pauVar14 = (undefined (*) [16])((int)(piStack156 + 0x48) + (int)piVar11);
            piVar11 = (int *)((int)piVar11 - (int)piVar17);
            piStack160 = piVar17;
            do {
              auVar22 = pshufb(*pauVar14,auVar27);
              auVar21 = pshufb(pauVar14[-1],auVar27);
              pauVar12[-1] = auVar22;
              *pauVar12 = auVar21;
              pauVar12 = pauVar12[2];
              pauVar14 = pauVar14[-2];
              piStack160 = piStack160 + -8;
            } while (piStack160 != (int *)0x0);
            piStack116 = piVar11;
            piStack128 = piStack156;
            if (piVar17 == piVar5) goto LAB_00015209;
          }
        }
        do {
          *(byte *)((int)param_2 + (int)piVar17) = ((byte *)((int)piStack156 + 0x12f))[(int)piVar11]
          ;
          piStack116 = (int *)((int)piVar11 + -1);
          piVar17 = (int *)((int)piVar17 + 1);
          piStack160 = param_2;
          piStack128 = piStack156;
          if (param_3 <= piVar17) break;
          bVar20 = piVar11 != (int *)0x1;
          piVar11 = piStack116;
        } while (bVar20);
      }
LAB_00015209:
      ppiStack112 = (int **)&__stack_chk_guard;
      if (piVar17 < param_3) {
        pbStack84 = (byte *)((int)piStack156 + 0x131);
        piStack76 = param_2 + 4;
        pbStack72 = (byte *)((int)piStack156 + 0x121);
        iVar23 = 0x1002;
        iVar24 = 0x1002;
        iVar25 = 0x1002;
        iVar26 = 0x1002;
        auStack64 = _UNK_00017f30;
        auVar27 = _UNK_00017f30;
        piStack128 = piStack156;
        piStack100 = piVar6;
        iStack48 = iVar23;
        iStack44 = iVar24;
        iStack40 = iVar25;
        iStack36 = iVar26;
        do {
          piStack156 = (int *)param_1[0xe];
          uVar15 = piStack156[4];
          if (0xc < uVar15) {
            param_1[0xc] = 0x70;
            goto LAB_00015824;
          }
          uVar10 = piStack156[8];
          piStack120 = piVar17;
          if (uVar10 < uVar15) {
            piStack108 = piStack156 + 0xc;
            piStack96 = (int *)((int)piStack156 + 0x31);
            bVar3 = *(byte *)(piStack156 + 0xc);
            do {
              piVar11 = piStack108;
              if (bVar3 == 0) {
                piStack140 = piStack108;
                piStack144 = param_1;
                piStack136 = (int *)0x1;
                puStack148 = (undefined *)0x152d2;
                cVar2 = (**(code **)(param_1[0xe] + 0x2c))();
                if (cVar2 != '\x01') {
                  param_1[0xc] = 0x66;
                  param_1 = piVar11;
                  goto LAB_00015824;
                }
                if (*(byte *)piVar11 == 0) goto LAB_000157e6;
                piStack136 = (int *)(uint)*(byte *)piVar11;
                piStack140 = piStack96;
                piStack144 = param_1;
                puStack148 = (undefined *)0x15300;
                uVar13 = (**(code **)(param_1[0xe] + 0x2c))();
                if ((byte)uVar13 != *(byte *)piStack108) goto LAB_000157dd;
                bVar9 = *(byte *)((int)piStack156 + 0x31);
                *(byte *)((int)piStack156 + 0x31) = 2;
                uVar15 = piStack156[4];
                uVar10 = piStack156[8];
                auVar27 = auStack64;
                iVar23 = iStack48;
                iVar24 = iStack44;
                iVar25 = iStack40;
                iVar26 = iStack36;
              }
              else {
                bVar9 = *(byte *)((int)piStack156 + 0x31);
                uVar13 = (uint)CONCAT11(bVar9 + 1,bVar3);
                *(byte *)((int)piStack156 + 0x31) = (byte)(uVar13 >> 8);
                bVar9 = *(byte *)((int)piStack156 + bVar9 + 0x30);
              }
              bVar3 = (char)uVar13 - 1;
              *(byte *)(piStack156 + 0xc) = bVar3;
              uVar13 = (uint)bVar9 << ((byte)uVar10 & 0x1f) | piStack156[9];
              piStack156[9] = uVar13;
              uVar10 = uVar10 + 8;
              piStack156[8] = uVar10;
            } while (uVar10 < uVar15);
          }
          else {
            uVar13 = piStack156[9];
          }
          piVar6 = (int *)(*(ushort *)((int)ppuStack104 + uVar15 * 2 + -0x2fe4) & uVar13);
          piStack156[9] = uVar13 >> ((byte)uVar15 & 0x1f);
          piStack156[8] = uVar10 - uVar15;
          if ((uint)piStack156[3] < 0x1001) {
            uVar10 = piStack156[3] + 1;
            piStack156[3] = uVar10;
            if ((uVar15 < 0xc) && ((uint)piStack156[5] < uVar10)) {
              piStack156[5] = piStack156[5] * 2;
              piStack156[4] = uVar15 + 1;
            }
          }
          if (piVar6 == piStack68) {
            param_1[0xc] = 0x71;
            goto LAB_00015824;
          }
          if (piVar6 == piStack92) {
            iVar7 = -0x1000;
            do {
              piVar11 = piStack128 + iVar7 + 0x184c;
              *piVar11 = iVar23;
              piVar11[1] = iVar24;
              piVar11[2] = iVar25;
              piVar11[3] = iVar26;
              piVar11 = piStack128 + iVar7 + 0x1850;
              *piVar11 = iVar23;
              piVar11[1] = iVar24;
              piVar11[2] = iVar25;
              piVar11[3] = iVar26;
              iVar7 = iVar7 + 8;
            } while (iVar7 != 0);
            piStack128[3] = piStack128[2] + 1;
            piStack128[4] = *piStack128 + 1;
            piStack128[5] = 1 << ((byte)(*piStack128 + 1) & 0x1f);
            piStack128[6] = 0x1002;
            piVar6 = (int *)0x1002;
          }
          else {
            piStack108 = piVar6;
            if ((int)piStack92 <= (int)piVar6) {
              piVar17 = piVar6;
              piVar5 = piStack116;
              piVar11 = param_1;
              if (piStack128[(int)(piVar6 + 0x213)] == 0x1002) {
                if (piVar6 != (int *)(piStack128[3] + -2)) {
                  param_1[0xc] = 0x70;
                  ppiVar16 = ppiStack112;
                  goto LAB_000150c5;
                }
                piVar11 = piStack100;
                if ((int)piStack92 < (int)piStack100) {
                  iVar7 = 1;
                  while ((int)piVar11 < 0x1000) {
                    piVar11 = (int *)piStack128[(int)(piVar11 + 0x213)];
                    if ((0xfff < iVar7) ||
                       (iVar7 = iVar7 + (uint)((int)piStack92 < (int)piVar11),
                       (int)piVar11 <= (int)piStack92)) goto LAB_0001556c;
                  }
                  piVar11 = (int *)0x1002;
                }
LAB_0001556c:
                *(byte *)((int)(piStack128 + 0x4c) + (int)piStack116) = (byte)piVar11;
                *(byte *)((int)piStack128 + piStack128[3] + 0x112d) = (byte)piVar11;
                piStack156 = piStack100;
                piVar17 = piStack100;
                piVar5 = (int *)((int)piStack116 + 1);
                piVar11 = piStack128;
              }
              if ((int)piVar5 < 0xfff) {
                pauVar12 = (undefined (*) [16])(pbStack72 + (int)piVar5);
                piStack156 = (int *)~(uint)piVar5;
                while (((int)piStack92 < (int)piVar17 && ((int)piVar17 < 0x1000))) {
                  *(byte *)((int)(piStack128 + 0x4c) + (int)piVar5) =
                       ((byte *)((int)piStack128 + 0x112f))[(int)piVar17];
                  piVar17 = (int *)piStack128[(int)(piVar17 + 0x213)];
                  pauVar12 = (undefined (*) [16])(*pauVar12 + 1);
                  piStack156 = (int *)((int)piStack156 - 1);
                  bVar20 = 0xffd < (int)piVar5;
                  piVar5 = (int *)((int)piVar5 + 1);
                  piVar11 = piStack128;
                  if (bVar20) goto LAB_000157e6;
                }
                if ((int)piVar17 < 0x1000) {
                  piVar11 = (int *)((int)piVar5 + 1);
                  *(byte *)((int)(piStack128 + 0x4c) + (int)piVar5) = (byte)piVar17;
                  piVar17 = (int *)((int)piStack120 - (int)piStack124);
                  piStack116 = piVar11;
                  if ((piStack120 < piStack124) && (piVar11 != (int *)0x0)) {
                    piVar18 = (int *)~(uint)piVar5;
                    piVar8 = piVar18;
                    if (piVar18 < piVar17) {
                      piVar8 = piVar17;
                    }
                    piVar8 = (int *)-(int)piVar8;
                    if ((int *)0x1f < piVar8) {
                      piStack96 = (int *)((int)param_2 + (int)piStack120);
                      piVar19 = piVar18;
                      if (piVar18 < piVar17) {
                        piVar19 = piVar17;
                      }
                      piStack88 = piVar8;
                      piStack80 = piVar18;
                      if ((pbStack84 + (int)piVar5 <= piStack96) ||
                         ((byte *)(((int)piStack120 - (int)piVar19) + (int)param_2) <=
                          (byte *)((int)piVar5 + (int)piVar19) + (int)pbStack84)) {
                        piStack96 = (int *)((uint)piVar8 & 0xffffffe0);
                        piVar11 = (int *)((int)piVar11 - (int)piStack96);
                        pauVar14 = (undefined (*) [16])((int)piStack76 + (int)piStack120);
                        piStack120 = (int *)((int)piStack120 + (int)piStack96);
                        if (piVar17 < piStack156) {
                          piVar17 = piStack156;
                        }
                        uVar15 = -(int)piVar17 & 0xffffffe0;
                        do {
                          auVar22 = pshufb(*pauVar12,auVar27);
                          auVar21 = pshufb(pauVar12[-1],auVar27);
                          pauVar14[-1] = auVar22;
                          *pauVar14 = auVar21;
                          pauVar14 = pauVar14[2];
                          pauVar12 = pauVar12[-2];
                          uVar15 = uVar15 - 0x20;
                        } while (uVar15 != 0);
                        piStack116 = piVar11;
                        if (piStack96 == piVar8) goto LAB_00015416;
                      }
                    }
                    do {
                      *(byte *)((int)param_2 + (int)piStack120) =
                           ((byte *)((int)piStack128 + 0x12f))[(int)piVar11];
                      piStack116 = (int *)((int)piVar11 + -1);
                      piStack120 = (int *)((int)piStack120 + 1);
                      if (piStack124 <= piStack120) break;
                      bVar20 = piVar11 != (int *)0x1;
                      piVar11 = piStack116;
                    } while (bVar20);
                  }
                  goto LAB_00015416;
                }
              }
LAB_000157e6:
              param_1[0xc] = 0x70;
              param_1 = piVar11;
              goto LAB_00015824;
            }
            *(byte *)((int)param_2 + (int)piStack120) = (byte)piVar6;
            piStack120 = (int *)((int)piStack120 + 1);
LAB_00015416:
            if ((piStack100 != (int *)0x1002) && (piStack128[piStack128[3] + 0x84a] == 0x1002)) {
              piStack128[piStack128[3] + 0x84a] = (int)piStack100;
              if (piVar6 != (int *)(piStack128[3] + -2)) {
                piStack100 = piVar6;
              }
              if ((int)piStack92 < (int)piStack100) {
                iVar7 = 1;
                while ((int)piStack100 < 0x1000) {
                  piStack100 = (int *)piStack128[(int)(piStack100 + 0x213)];
                  if ((0xfff < iVar7) ||
                     (iVar7 = iVar7 + (uint)((int)piStack92 < (int)piStack100),
                     (int)piStack100 <= (int)piStack92)) goto LAB_0001572a;
                }
                piStack100 = (int *)0x1002;
              }
LAB_0001572a:
              ((byte *)((int)piStack128 + 0x112f))[(int)(int *)(piStack128[3] + -2)] =
                   (byte)piStack100;
            }
          }
          piVar17 = piStack120;
          piStack160 = param_1;
          piStack156 = piStack128;
          piStack100 = piVar6;
        } while (piStack120 < piStack124);
      }
      piStack156[6] = (int)piVar6;
      piStack156[7] = (int)piStack116;
      uVar4 = 1;
      ppiVar16 = ppiStack112;
      piStack100 = piVar6;
      if (piStack156[10] == 0) {
        piStack156 = (int *)param_1[0xe];
        while( true ) {
          piStack140 = (int *)&bStack25;
          piStack144 = param_1;
          piStack136 = (int *)0x1;
          puStack148 = (undefined *)0x157a9;
          cVar2 = (*(code *)piStack156[0xb])();
          if (cVar2 != '\x01') break;
          if (bStack25 == 0) {
            *(byte *)(piStack156 + 0xc) = 0;
            piStack156[10] = 0;
            uVar4 = 1;
            ppiVar16 = ppiStack112;
            piStack160 = param_1;
            goto LAB_0001582a;
          }
          *(byte *)(piStack156 + 0xc) = bStack25;
          piStack156 = (int *)((int)piStack156 + 0x31);
          piStack136 = (int *)(uint)bStack25;
          piStack144 = param_1;
          puStack148 = (undefined *)0x157d7;
          piStack140 = piStack156;
          bVar3 = (**(code **)(param_1[0xe] + 0x2c))();
          if (bVar3 != bStack25) break;
          piStack156 = (int *)param_1[0xe];
        }
LAB_000157dd:
        param_1[0xc] = 0x66;
LAB_00015824:
        uVar4 = 0;
        ppiVar16 = ppiStack112;
        piStack160 = param_1;
      }
    }
  }
  else {
    param_1[0xc] = 0x6c;
    param_1 = param_3;
LAB_000150c5:
    uVar4 = 0;
    piStack160 = param_1;
  }
LAB_0001582a:
  ppuStack152 = ppuStack104;
  if (*ppiVar16 == piStack24) {
    return uVar4;
  }
  puStack148 = (undefined *)0x15852;
  func_0x00011af0();
  piStack208 = piStack140;
  ppuStack200 = &__DT_PLTGOT;
  ppiStack176 = (int **)&__stack_chk_guard;
  piStack168 = ___stack_chk_guard;
  iStack204 = piStack140[0xe];
  pbStack188 = &bStack169;
  piStack192 = piStack140;
  puStack184 = (uint *)0x1;
  puStack196 = (undefined *)0x158a4;
  puStack148 = &stack0xfffffffc;
  cVar2 = (**(code **)(iStack204 + 0x2c))();
  if (cVar2 == '\x01') {
    if (bStack169 == 0) {
      *piStack136 = 0;
      *(undefined *)(iStack204 + 0x30) = 0;
      *(undefined4 *)(iStack204 + 0x28) = 0;
      uVar4 = 1;
    }
    else {
      *piStack136 = iStack204 + 0x30;
      *(byte *)(iStack204 + 0x30) = bStack169;
      pbStack188 = (byte *)(*piStack136 + 1);
      puStack184 = (uint *)(uint)bStack169;
      piStack192 = piStack208;
      puStack196 = (undefined *)0x158d2;
      bVar3 = (**(code **)(piStack208[0xe] + 0x2c))();
      uVar4 = 1;
      if (bVar3 != bStack169) goto LAB_000158df;
    }
  }
  else {
LAB_000158df:
    piStack208[0xc] = 0x66;
    uVar4 = 0;
  }
  if (*ppiStack176 == piStack168) {
    return uVar4;
  }
  puStack196 = (undefined *)0x15919;
  func_0x00011af0();
  pbVar1 = pbStack188;
  puStack228 = &LAB_00015931;
  piStack216 = ___stack_chk_guard;
  pbStack236 = (byte *)((int)&uStack220 + 2);
  ppuStack232 = (undefined **)0x1;
  ppiStack240 = (int **)pbStack188;
  uStack244 = 0x15958;
  puStack196 = (undefined *)&puStack148;
  cVar2 = (**(code **)(*(int *)(pbStack188 + 0x38) + 0x2c))();
  ppiVar16 = (int **)&__stack_chk_guard;
  if (cVar2 == '\x01') {
    *puStack184 = uStack220 >> 0x10 & 0xff;
    iVar23 = *(int *)(pbVar1 + 0x38);
    pbStack236 = (byte *)((int)&uStack220 + 3);
    ppuStack232 = (undefined **)0x1;
    ppiStack240 = (int **)pbVar1;
    uStack244 = 0x1597d;
    ppiStack224 = (int **)&__stack_chk_guard;
    cVar2 = (**(code **)(iVar23 + 0x2c))();
    ppiVar16 = ppiStack224;
    if (cVar2 == '\x01') {
      if (uStack220._3_1_ == 0) {
        *piStack180 = 0;
        uVar4 = 1;
      }
      else {
        *piStack180 = iVar23 + 0x30;
        *(byte *)(iVar23 + 0x30) = uStack220._3_1_;
        pbStack236 = (byte *)(*piStack180 + 1);
        ppuStack232 = (undefined **)(uint)uStack220._3_1_;
        ppiStack240 = (int **)pbVar1;
        uStack244 = 0x159b1;
        cVar2 = (**(code **)(*(int *)(pbVar1 + 0x38) + 0x2c))();
        uVar4 = 1;
        ppiVar16 = ppiStack224;
        if (cVar2 != uStack220._3_1_) goto LAB_000159c4;
      }
    }
    else {
      *(undefined4 *)(pbVar1 + 0x30) = 0x66;
      uVar4 = 0;
    }
  }
  else {
LAB_000159c4:
    *(undefined4 *)(pbVar1 + 0x30) = 0x66;
    uVar4 = 0;
  }
  if (*ppiVar16 == piStack216) {
    return uVar4;
  }
  puStack228 = (undefined *)0x159fd;
  func_0x00011af0();
  pbStack236 = pbVar1;
  piStack248 = ___stack_chk_guard;
  iVar23 = *(int *)(uStack220 + 0x38);
  pbStack268 = &bStack249;
  pbStack264 = (byte *)0x1;
  ppiStack240 = ppiVar16;
  ppuStack232 = &__DT_PLTGOT;
  puStack228 = (undefined *)&puStack196;
  cVar2 = (**(code **)(iVar23 + 0x2c))(uStack220);
  if (cVar2 == '\x01') {
    if (bStack249 == 0) {
      *piStack216 = 0;
      uVar4 = 1;
      goto LAB_00015a95;
    }
    *piStack216 = iVar23 + 0x30;
    *(byte *)(iVar23 + 0x30) = bStack249;
    pbStack268 = (byte *)(*piStack216 + 1);
    pbStack264 = (byte *)(uint)bStack249;
    bVar3 = (**(code **)(*(int *)(uStack220 + 0x38) + 0x2c))(uStack220);
    uVar4 = 1;
    if (bVar3 == bStack249) goto LAB_00015a95;
  }
  *(undefined4 *)(uStack220 + 0x30) = 0x66;
  uVar4 = 0;
LAB_00015a95:
  if (___stack_chk_guard != piStack248) {
    func_0x00011af0();
    uVar4 = 0;
    if (pbStack268 == (byte *)0x4) {
      *pbStack260 = *pbStack264 >> 2 & 7;
      *(uint *)(pbStack260 + 4) = (uint)*(ushort *)(pbStack264 + 1);
      uVar15 = 0xffffffff;
      if ((*pbStack264 & 1) != 0) {
        uVar15 = (uint)pbStack264[3];
      }
      *(uint *)(pbStack260 + 8) = uVar15;
      uVar4 = 1;
    }
    return uVar4;
  }
  return uVar4;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00015860(int param_1,int *param_2)

{
  int iVar1;
  byte *pbVar2;
  char cVar3;
  byte bVar4;
  undefined4 uVar5;
  uint uVar6;
  int **ppiVar7;
  byte *pbStack124;
  byte *pbStack120;
  byte *pbStack116;
  byte bStack105;
  int *piStack104;
  undefined4 uStack100;
  int **ppiStack96;
  byte *pbStack92;
  undefined **ppuStack88;
  undefined *puStack84;
  int **ppiStack80;
  undefined4 uStack76;
  int *piStack72;
  int iStack64;
  int iStack60;
  undefined **ppuStack56;
  undefined *puStack52;
  int iStack48;
  byte *pbStack44;
  uint *puStack40;
  int *piStack36;
  int **ppiStack32;
  byte bStack25;
  int *piStack24;
  
  ppuStack56 = &__DT_PLTGOT;
  ppiStack32 = (int **)&__stack_chk_guard;
  piStack24 = ___stack_chk_guard;
  iStack60 = *(int *)(param_1 + 0x38);
  pbStack44 = &bStack25;
  iStack48 = param_1;
  puStack40 = (uint *)0x1;
  puStack52 = (undefined *)0x158a4;
  cVar3 = (**(code **)(iStack60 + 0x2c))();
  if (cVar3 == '\x01') {
    if (bStack25 == 0) {
      *param_2 = 0;
      *(undefined *)(iStack60 + 0x30) = 0;
      *(undefined4 *)(iStack60 + 0x28) = 0;
      uVar5 = 1;
    }
    else {
      *param_2 = iStack60 + 0x30;
      *(byte *)(iStack60 + 0x30) = bStack25;
      pbStack44 = (byte *)(*param_2 + 1);
      puStack40 = (uint *)(uint)bStack25;
      iStack48 = param_1;
      puStack52 = (undefined *)0x158d2;
      bVar4 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
      uVar5 = 1;
      if (bVar4 != bStack25) goto LAB_000158df;
    }
  }
  else {
LAB_000158df:
    *(undefined4 *)(param_1 + 0x30) = 0x66;
    uVar5 = 0;
  }
  if (*ppiStack32 == piStack24) {
    return uVar5;
  }
  puStack52 = (undefined *)0x15919;
  func_0x00011af0();
  pbVar2 = pbStack44;
  iStack64 = param_1;
  puStack84 = &LAB_00015931;
  piStack72 = ___stack_chk_guard;
  pbStack92 = (byte *)((int)&uStack76 + 2);
  ppuStack88 = (undefined **)0x1;
  ppiStack96 = (int **)pbStack44;
  uStack100 = 0x15958;
  puStack52 = &stack0xfffffffc;
  cVar3 = (**(code **)(*(int *)(pbStack44 + 0x38) + 0x2c))();
  ppiVar7 = (int **)&__stack_chk_guard;
  if (cVar3 == '\x01') {
    *puStack40 = uStack76 >> 0x10 & 0xff;
    iVar1 = *(int *)(pbVar2 + 0x38);
    pbStack92 = (byte *)((int)&uStack76 + 3);
    ppuStack88 = (undefined **)0x1;
    ppiStack96 = (int **)pbVar2;
    uStack100 = 0x1597d;
    ppiStack80 = (int **)&__stack_chk_guard;
    cVar3 = (**(code **)(iVar1 + 0x2c))();
    ppiVar7 = ppiStack80;
    if (cVar3 == '\x01') {
      if (uStack76._3_1_ == 0) {
        *piStack36 = 0;
        uVar5 = 1;
      }
      else {
        *piStack36 = iVar1 + 0x30;
        *(byte *)(iVar1 + 0x30) = uStack76._3_1_;
        pbStack92 = (byte *)(*piStack36 + 1);
        ppuStack88 = (undefined **)(uint)uStack76._3_1_;
        ppiStack96 = (int **)pbVar2;
        uStack100 = 0x159b1;
        cVar3 = (**(code **)(*(int *)(pbVar2 + 0x38) + 0x2c))();
        uVar5 = 1;
        ppiVar7 = ppiStack80;
        if (cVar3 != uStack76._3_1_) goto LAB_000159c4;
      }
    }
    else {
      *(undefined4 *)(pbVar2 + 0x30) = 0x66;
      uVar5 = 0;
    }
  }
  else {
LAB_000159c4:
    *(undefined4 *)(pbVar2 + 0x30) = 0x66;
    uVar5 = 0;
  }
  if (*ppiVar7 == piStack72) {
    return uVar5;
  }
  puStack84 = (undefined *)0x159fd;
  func_0x00011af0();
  pbStack92 = pbVar2;
  piStack104 = ___stack_chk_guard;
  iVar1 = *(int *)(uStack76 + 0x38);
  pbStack124 = &bStack105;
  pbStack120 = (byte *)0x1;
  ppiStack96 = ppiVar7;
  ppuStack88 = &__DT_PLTGOT;
  puStack84 = (undefined *)&puStack52;
  cVar3 = (**(code **)(iVar1 + 0x2c))(uStack76);
  if (cVar3 == '\x01') {
    if (bStack105 == 0) {
      *piStack72 = 0;
      uVar5 = 1;
      goto LAB_00015a95;
    }
    *piStack72 = iVar1 + 0x30;
    *(byte *)(iVar1 + 0x30) = bStack105;
    pbStack124 = (byte *)(*piStack72 + 1);
    pbStack120 = (byte *)(uint)bStack105;
    bVar4 = (**(code **)(*(int *)(uStack76 + 0x38) + 0x2c))(uStack76);
    uVar5 = 1;
    if (bVar4 == bStack105) goto LAB_00015a95;
  }
  *(undefined4 *)(uStack76 + 0x30) = 0x66;
  uVar5 = 0;
LAB_00015a95:
  if (___stack_chk_guard != piStack104) {
    func_0x00011af0();
    uVar5 = 0;
    if (pbStack124 == (byte *)0x4) {
      *pbStack116 = *pbStack120 >> 2 & 7;
      *(uint *)(pbStack116 + 4) = (uint)*(ushort *)(pbStack120 + 1);
      uVar6 = 0xffffffff;
      if ((*pbStack120 & 1) != 0) {
        uVar6 = (uint)pbStack120[3];
      }
      *(uint *)(pbStack116 + 8) = uVar6;
      uVar5 = 1;
    }
    return uVar5;
  }
  return uVar5;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00015920(int param_1,uint *param_2,int *param_3)

{
  int iVar1;
  char cVar2;
  byte bVar3;
  undefined4 uVar4;
  uint uVar5;
  int **ppiVar6;
  byte *pbStack76;
  byte *pbStack72;
  byte *pbStack68;
  byte bStack57;
  int *piStack56;
  undefined4 uStack52;
  int **ppiStack48;
  int iStack44;
  undefined **ppuStack40;
  undefined *puStack36;
  int **ppiStack32;
  undefined4 uStack28;
  int *piStack24;
  
  puStack36 = &LAB_00015931;
  piStack24 = ___stack_chk_guard;
  iStack44 = (int)&uStack28 + 2;
  ppuStack40 = (undefined **)0x1;
  ppiStack48 = (int **)param_1;
  uStack52 = 0x15958;
  cVar2 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
  ppiVar6 = (int **)&__stack_chk_guard;
  if (cVar2 == '\x01') {
    *param_2 = uStack28 >> 0x10 & 0xff;
    iVar1 = *(int *)(param_1 + 0x38);
    iStack44 = (int)&uStack28 + 3;
    ppuStack40 = (undefined **)0x1;
    ppiStack48 = (int **)param_1;
    uStack52 = 0x1597d;
    ppiStack32 = (int **)&__stack_chk_guard;
    cVar2 = (**(code **)(iVar1 + 0x2c))();
    ppiVar6 = ppiStack32;
    if (cVar2 == '\x01') {
      if (uStack28._3_1_ == 0) {
        *param_3 = 0;
        uVar4 = 1;
      }
      else {
        *param_3 = iVar1 + 0x30;
        *(byte *)(iVar1 + 0x30) = uStack28._3_1_;
        iStack44 = *param_3 + 1;
        ppuStack40 = (undefined **)(uint)uStack28._3_1_;
        ppiStack48 = (int **)param_1;
        uStack52 = 0x159b1;
        cVar2 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))();
        uVar4 = 1;
        ppiVar6 = ppiStack32;
        if (cVar2 != uStack28._3_1_) goto LAB_000159c4;
      }
    }
    else {
      *(undefined4 *)(param_1 + 0x30) = 0x66;
      uVar4 = 0;
    }
  }
  else {
LAB_000159c4:
    *(undefined4 *)(param_1 + 0x30) = 0x66;
    uVar4 = 0;
  }
  if (*ppiVar6 == piStack24) {
    return uVar4;
  }
  puStack36 = (undefined *)0x159fd;
  func_0x00011af0();
  iStack44 = param_1;
  piStack56 = ___stack_chk_guard;
  iVar1 = *(int *)(uStack28 + 0x38);
  pbStack76 = &bStack57;
  pbStack72 = (byte *)0x1;
  ppiStack48 = ppiVar6;
  ppuStack40 = &__DT_PLTGOT;
  puStack36 = &stack0xfffffffc;
  cVar2 = (**(code **)(iVar1 + 0x2c))(uStack28);
  if (cVar2 == '\x01') {
    if (bStack57 == 0) {
      *piStack24 = 0;
      uVar4 = 1;
      goto LAB_00015a95;
    }
    *piStack24 = iVar1 + 0x30;
    *(byte *)(iVar1 + 0x30) = bStack57;
    pbStack76 = (byte *)(*piStack24 + 1);
    pbStack72 = (byte *)(uint)bStack57;
    bVar3 = (**(code **)(*(int *)(uStack28 + 0x38) + 0x2c))(uStack28);
    uVar4 = 1;
    if (bVar3 == bStack57) goto LAB_00015a95;
  }
  *(undefined4 *)(uStack28 + 0x30) = 0x66;
  uVar4 = 0;
LAB_00015a95:
  if (___stack_chk_guard != piStack56) {
    func_0x00011af0();
    uVar4 = 0;
    if (pbStack76 == (byte *)0x4) {
      *pbStack68 = *pbStack72 >> 2 & 7;
      *(uint *)(pbStack68 + 4) = (uint)*(ushort *)(pbStack72 + 1);
      uVar5 = 0xffffffff;
      if ((*pbStack72 & 1) != 0) {
        uVar5 = (uint)pbStack72[3];
      }
      *(uint *)(pbStack68 + 8) = uVar5;
      uVar4 = 1;
    }
    return uVar4;
  }
  return uVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00015a00(int param_1,int *param_2)

{
  int iVar1;
  char cVar2;
  byte bVar3;
  undefined4 uVar4;
  uint uVar5;
  byte *pbStack44;
  byte *pbStack40;
  byte *pbStack36;
  byte bStack25;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  iVar1 = *(int *)(param_1 + 0x38);
  pbStack44 = &bStack25;
  pbStack40 = (byte *)0x1;
  cVar2 = (**(code **)(iVar1 + 0x2c))(param_1);
  if (cVar2 == '\x01') {
    if (bStack25 == 0) {
      *param_2 = 0;
      uVar4 = 1;
      goto LAB_00015a95;
    }
    *param_2 = iVar1 + 0x30;
    *(byte *)(iVar1 + 0x30) = bStack25;
    pbStack44 = (byte *)(*param_2 + 1);
    pbStack40 = (byte *)(uint)bStack25;
    bVar3 = (**(code **)(*(int *)(param_1 + 0x38) + 0x2c))(param_1);
    uVar4 = 1;
    if (bVar3 == bStack25) goto LAB_00015a95;
  }
  *(undefined4 *)(param_1 + 0x30) = 0x66;
  uVar4 = 0;
LAB_00015a95:
  if (___stack_chk_guard == iStack24) {
    return uVar4;
  }
  func_0x00011af0();
  uVar4 = 0;
  if (pbStack44 == (byte *)0x4) {
    *pbStack36 = *pbStack40 >> 2 & 7;
    *(uint *)(pbStack36 + 4) = (uint)*(ushort *)(pbStack40 + 1);
    uVar5 = 0xffffffff;
    if ((*pbStack40 & 1) != 0) {
      uVar5 = (uint)pbStack40[3];
    }
    *(uint *)(pbStack36 + 8) = uVar5;
    uVar4 = 1;
  }
  return uVar4;
}



undefined4 FUN_00015ab0(int param_1,byte *param_2,byte *param_3)

{
  undefined4 uVar1;
  uint uVar2;
  
  uVar1 = 0;
  if (param_1 == 4) {
    *param_3 = *param_2 >> 2 & 7;
    *(uint *)(param_3 + 4) = (uint)*(ushort *)(param_2 + 1);
    uVar2 = 0xffffffff;
    if ((*param_2 & 1) != 0) {
      uVar2 = (uint)param_2[3];
    }
    *(uint *)(param_3 + 8) = uVar2;
    uVar1 = 1;
  }
  return uVar1;
}



undefined4 FUN_00015b00(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if ((param_1 != 0) && (*(int *)(param_1 + 0x38) != 0)) {
    if (*(int *)(param_1 + 0x28) != 0) {
      FUN_00015c20(*(int *)(param_1 + 0x28));
      *(undefined4 *)(param_1 + 0x28) = 0;
    }
    if (*(int *)(param_1 + 0xc) != 0) {
      FUN_00015c20(*(int *)(param_1 + 0xc));
      *(undefined4 *)(param_1 + 0xc) = 0;
    }
    if (*(int *)(param_1 + 0x2c) != 0) {
      FUN_00015c60(param_1);
      *(undefined4 *)(param_1 + 0x2c) = 0;
    }
    func_0x00011b80(*(undefined4 *)(param_1 + 0x38));
    func_0x00011b80(param_1);
    uVar1 = 1;
  }
  return uVar1;
}



int * FUN_00015b90(byte param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  
  piVar1 = (int *)func_0x00011c20(0xc);
  piVar3 = (int *)0x0;
  if (piVar1 != (int *)0x0) {
    iVar2 = func_0x00011ba0(0x100,3);
    piVar1[2] = iVar2;
    if (iVar2 == 0) {
      func_0x00011b80(piVar1);
    }
    else {
      *piVar1 = 1 << (param_1 & 0x1f);
      *(byte *)(piVar1 + 1) = param_1;
      piVar3 = piVar1;
      if (param_2 != 0) {
        func_0x00011b60(iVar2,param_2,3 << (param_1 & 0x1f));
      }
    }
  }
  return piVar3;
}



void FUN_00015c20(int param_1)

{
  if (param_1 != 0) {
    func_0x00011b80(*(undefined4 *)(param_1 + 8));
    func_0x00011b80(param_1);
  }
  return;
}



void FUN_00015c60(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  if ((param_1 != 0) && (uVar2 = *(uint *)(param_1 + 0x2c), uVar2 != 0)) {
    iVar3 = *(int *)(param_1 + 0x10);
    uVar4 = uVar2;
    if (0 < iVar3) {
      do {
        iVar1 = *(int *)(uVar4 + 0x14);
        if (iVar1 != 0) {
          func_0x00011b80(*(undefined4 *)(iVar1 + 8));
          func_0x00011b80(iVar1);
          *(undefined4 *)(uVar4 + 0x14) = 0;
          iVar3 = *(int *)(param_1 + 0x10);
          uVar2 = *(uint *)(param_1 + 0x2c);
        }
        uVar4 = uVar4 + 0x18;
      } while (uVar4 < uVar2 + iVar3 * 0x18);
    }
    func_0x00011b80(uVar2);
    *(undefined4 *)(param_1 + 0x2c) = 0;
  }
  return;
}



undefined4 FUN_00015cf0(undefined4 param_1,uint param_2,uint param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (((param_2 == 0) || ((param_3 | param_2) < 0x10000)) ||
     (param_3 <= (uint)(0xffffffff / (ulonglong)param_2))) {
    uVar2 = func_0x00011ca0(param_1,param_3 * param_2);
  }
  else {
    puVar1 = (undefined4 *)func_0x00011bb0();
    *puVar1 = 0xc;
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 * FUN_00015d50(int **param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined *puVar3;
  int *piVar4;
  bool bVar5;
  int *piVar6;
  
  piVar6 = param_1[3];
  if ((int)piVar6 < 0) {
    param_1[1] = (int *)0x6f;
    piVar4 = (int *)0x6f;
LAB_00015eb7:
    bVar5 = false;
    if (param_1[4] == (int *)FUN_00013a50) {
      bVar5 = piVar4 == (int *)0x66 || piVar4 == (int *)0x6f;
    }
    FUN_00013930(piVar4,param_2,bVar5);
    FUN_00015b00(*param_1);
    return (undefined4 *)0x0;
  }
  piVar4 = param_1[1];
  if (piVar4 != (int *)0x0) goto LAB_00015eb7;
  piVar4 = *param_1;
  if (piVar4 == (int *)0x0) {
    piVar4 = (int *)0x0;
    goto LAB_00015eb7;
  }
  piVar1 = param_1[2];
  puVar2 = (undefined4 *)func_0x00011c20(0x68);
  if (puVar2 != (undefined4 *)0x0) {
    puVar3 = (undefined *)func_0x00011c20(0xc);
    puVar2[10] = puVar3;
    if (puVar3 != (undefined *)0x0) {
      *(undefined4 *)(puVar3 + 4) = 100;
      *(undefined4 *)(puVar3 + 8) = 0xffffffff;
      *puVar3 = 0;
      *puVar2 = 0;
      puVar2[1] = piVar4;
      puVar2[0xd] = piVar6;
      puVar2[0xc] = piVar1;
      puVar2[9] = 0;
      puVar2[5] = 0xffffffff;
      puVar2[6] = 0xffffffff;
      puVar2[7] = 0;
      puVar2[8] = 0;
      puVar2[0x10] = 0;
      puVar2[0x11] = 1;
      puVar2[0x12] = 0;
      puVar2[0x14] = 0x3f800000;
      piVar6 = param_1[5];
      puVar2[0x17] = param_1[6];
      puVar2[0x16] = piVar6;
      puVar2[0xb] = 0;
      puVar2[0x13] = param_1[4];
      puVar2[0x19] = 0;
      *(undefined *)(puVar2 + 0x18) = 0;
      puVar2[4] = 1;
      FUN_000126e0(puVar2,0,0);
      puVar2[0xe] = 0;
      puVar2[0xf] = 0;
      puVar2[3] = ((undefined4 *)puVar2[1])[1];
      puVar2[2] = *(undefined4 *)puVar2[1];
      piVar6 = *param_1;
      if ((*piVar6 == 0) || (piVar6[1] == 0)) {
        FUN_00015b00(piVar6);
        piVar6 = (int *)0x3e9;
        goto LAB_00015f98;
      }
      if (piVar6[0xc] == 0x6d) {
        FUN_00012f80(puVar2);
        goto LAB_00015f0f;
      }
      if (piVar6[4] == 0) {
        piVar4 = (int *)0x3e8;
LAB_00015f75:
        param_1[1] = piVar4;
      }
      else {
        piVar4 = (int *)0x3ec;
        if (piVar6[0xc] == 0x3ec) goto LAB_00015f75;
        if (param_1[1] == (int *)0x0) {
          return puVar2;
        }
      }
      FUN_00012f80(puVar2);
      piVar6 = param_1[1];
LAB_00015f98:
      FUN_00013930(piVar6,param_2,0);
      return (undefined4 *)0x0;
    }
  }
  FUN_00015b00(piVar4);
LAB_00015f0f:
  FUN_00013760(param_2,2,&UNK_00017c08);
  return (undefined4 *)0x0;
}



void FUN_00015fb0(undefined *param_1)

{
  *(undefined4 *)(param_1 + 4) = 100;
  *(undefined4 *)(param_1 + 8) = 0xffffffff;
  *param_1 = 0;
  return;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_setOptions
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,ushort param_5,
               char param_6)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_3 != 0) {
    *(bool *)(param_3 + 0x60) = param_6 == '\x01';
    uVar4 = (uint)param_5;
    *(uint *)(param_3 + 0x10) = uVar4;
    puVar2 = *(uint **)(param_3 + 4);
    uVar1 = *puVar2;
    uVar3 = puVar2[1];
    puVar2[1] = uVar3 / uVar4;
    *puVar2 = uVar1 / uVar4;
    if (uVar3 < uVar4) {
      puVar2[1] = 1;
    }
    if (uVar1 < uVar4) {
      *puVar2 = 1;
    }
    uVar1 = puVar2[4];
    if (uVar1 != 0) {
      puVar2 = (uint *)(puVar2[0xb] + 0xc);
      uVar3 = 0;
      do {
        puVar2[-1] = puVar2[-1] / uVar4;
        *puVar2 = *puVar2 / uVar4;
        puVar2[-3] = puVar2[-3] / uVar4;
        puVar2[-2] = puVar2[-2] / uVar4;
        uVar3 = uVar3 + 1;
        puVar2 = puVar2 + 6;
      } while (uVar3 < uVar1);
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00016080(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack28;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  iVar1 = (**(code **)(*piRam0001b014 + 0x10))(piRam0001b014,&uStack28,0x1b004);
  uVar2 = 0;
  if (iVar1 == 0) {
    uVar2 = uStack28;
  }
  if (___stack_chk_guard == iStack24) {
    return uVar2;
  }
  func_0x00011af0();
  uVar2 = (**(code **)(*piRam0001b014 + 0x14))(piRam0001b014);
  return uVar2;
}



void FUN_000160f0(void)

{
  (**(code **)(*piRam0001b014 + 0x14))(piRam0001b014);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 JNI_OnLoad(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  undefined auStack32 [8];
  undefined4 uStack24;
  int iStack20;
  
  iStack20 = ___stack_chk_guard;
  piRam0001b014 = param_1;
  iVar1 = (**(code **)(*param_1 + 0x18))(param_1,&uStack24,0x10006);
  uVar2 = 0xffffffff;
  if (iVar1 == 0) {
    iRam0001b018 = FUN_00015b90(8,0);
    if (iRam0001b018 == 0) {
      FUN_00013760(uStack24,2,&UNK_00017c08);
    }
    else {
      iVar1 = *(int *)(iRam0001b018 + 8);
      cVar3 = '\x01';
      iVar4 = -0x2fd;
      do {
        *(char *)(iVar1 + 0x300 + iVar4) = cVar3;
        *(char *)(iVar1 + 0x301 + iVar4) = cVar3;
        *(char *)(iVar1 + 0x302 + iVar4) = cVar3;
        cVar3 = cVar3 + '\x01';
        iVar4 = iVar4 + 3;
      } while (iVar4 != 0);
    }
    iVar1 = func_0x00011cb0(4,auStack32);
    if (iVar1 == -1) {
      FUN_00013760(uStack24,1,&UNK_00017c78);
    }
    uVar2 = 0x10006;
  }
  if (___stack_chk_guard != iStack20) {
    func_0x00011af0();
    uVar2 = FUN_00015c20(iRam0001b018);
    return uVar2;
  }
  return uVar2;
}



void JNI_OnUnload(void)

{
  FUN_00015c20(uRam0001b018);
  return;
}



undefined4 FUN_00016250(void)

{
  return uRam0001b018;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getComment(int *param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (**(code **)(*param_1 + 0x29c))(param_1,*(undefined4 *)(param_3 + 0x40));
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_isAnimationCompleted
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (((param_3 == 0) || (*(int *)(param_3 + 0x44) == 0)) ||
     (uVar1 = 1, *(int *)(param_3 + 0x48) != *(int *)(param_3 + 0x44))) {
    uVar1 = 0;
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getLoopCount
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(param_3 + 0x44);
  }
  return uVar1;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_setLoopCount
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,ushort param_5)

{
  if (param_3 != 0) {
    *(uint *)(param_3 + 0x44) = (uint)param_5;
  }
  return;
}



int Java_pl_droidsonroids_gif_GifInfoHandle_getDuration
              (undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  
  iVar2 = 0;
  if ((param_3 != 0) && (uVar1 = *(uint *)(*(int *)(param_3 + 4) + 0x10), uVar1 != 0)) {
    piVar3 = (int *)(*(int *)(param_3 + 0x28) + 4);
    iVar2 = 0;
    uVar4 = 0;
    do {
      iVar2 = iVar2 + *piVar3;
      uVar4 = uVar4 + 1;
      piVar3 = piVar3 + 3;
    } while (uVar4 < uVar1);
  }
  return iVar2;
}



undefined8
Java_pl_droidsonroids_gif_GifInfoHandle_getSourceLength
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  if (param_3 == 0) {
    uVar1 = 0xffffffff;
    uVar2 = 0xffffffff;
  }
  else {
    uVar1 = *(undefined4 *)(param_3 + 0x58);
    uVar2 = *(undefined4 *)(param_3 + 0x5c);
  }
  return CONCAT44(uVar2,uVar1);
}



int Java_pl_droidsonroids_gif_GifInfoHandle_getCurrentPosition
              (undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  uint uVar6;
  
  iVar5 = 0;
  if ((param_3 != 0) && (*(int *)(*(int *)(param_3 + 4) + 0x10) != 1)) {
    iVar3 = *(int *)(param_3 + 0x24);
    iVar5 = 0;
    if (iVar3 != 0) {
      piVar4 = (int *)(*(int *)(param_3 + 0x28) + 4);
      do {
        iVar5 = iVar5 + *piVar4;
        piVar4 = piVar4 + 3;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    uVar6 = *(uint *)(param_3 + 0x14);
    if ((*(uint *)(param_3 + 0x18) & uVar6) == 0xffffffff) {
      uVar1 = *(uint *)(param_3 + 0x1c);
      iVar3 = *(int *)(param_3 + 0x20);
      uVar2 = FUN_000179d0();
      uVar6 = uVar1 - uVar2;
      if ((int)((iVar3 - ((int)uVar2 >> 0x1f)) - (uint)(uVar1 < uVar2)) < 0) {
        uVar6 = 0;
      }
    }
    iVar5 = iVar5 - uVar6;
  }
  return iVar5;
}



int Java_pl_droidsonroids_gif_GifInfoHandle_getMetadataByteCount
              (undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  if (param_3 == 0) {
    iVar2 = 0;
  }
  else {
    iVar1 = *(int *)(*(int *)(param_3 + 4) + 0x10);
    iVar2 = 0;
    if (*(int *)(param_3 + 0x40) != 0) {
      iVar2 = func_0x00011b50(*(int *)(param_3 + 0x40));
    }
    iVar2 = iVar1 * 0x24 + 0xa4 + iVar2;
  }
  return iVar2;
}



uint Java_pl_droidsonroids_gif_GifInfoHandle_getAllocationByteCount
               (undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  char *pcVar10;
  int *piVar11;
  uint uVar12;
  bool bVar13;
  
  if (param_3 == 0) {
    uVar6 = 0;
  }
  else {
    uVar6 = *(uint *)(param_3 + 0x3c);
    if (uVar6 == 0) {
      uVar5 = *(uint *)(*(int *)(param_3 + 4) + 0x10);
      if (uVar5 == 0) {
        uVar6 = 0;
      }
      else {
        iVar9 = *(int *)(param_3 + 0xc);
        iVar1 = *(int *)(*(int *)(param_3 + 4) + 0x2c);
        iVar2 = *(int *)(iVar1 + 8);
        iVar3 = *(int *)(iVar1 + 0xc);
        uVar12 = iVar3 * iVar2;
        iVar4 = *(int *)(param_3 + 8);
        uVar6 = 0;
        if (iVar3 != iVar9 && -1 < iVar3 - iVar9) {
          uVar6 = uVar12;
        }
        if (iVar2 != iVar4 && -1 < iVar2 - iVar4) {
          uVar6 = uVar12;
        }
        if (uVar12 != 0) {
          uVar6 = uVar12;
        }
        if (uVar5 != 1) {
          piVar11 = (int *)(iVar1 + 0x24);
          uVar12 = 1;
          do {
            iVar1 = piVar11[-1];
            iVar2 = *piVar11;
            uVar8 = iVar2 * iVar1;
            uVar7 = uVar6;
            if (iVar2 != iVar9 && -1 < iVar2 - iVar9) {
              uVar7 = uVar8;
            }
            if (iVar1 != iVar4 && -1 < iVar1 - iVar4) {
              uVar7 = uVar8;
            }
            bVar13 = uVar6 <= uVar8;
            iVar1 = uVar8 - uVar6;
            uVar6 = uVar7;
            if (bVar13 && iVar1 != 0) {
              uVar6 = uVar8;
            }
            uVar12 = uVar12 + 1;
            piVar11 = piVar11 + 6;
          } while (uVar12 < uVar5);
        }
      }
    }
    if (*(int *)(param_3 + 0x2c) == 0) {
      uVar5 = *(uint *)(*(int *)(param_3 + 4) + 0x10);
      if (1 < uVar5) {
        pcVar10 = *(char **)(param_3 + 0x28);
        uVar12 = 1;
        do {
          pcVar10 = pcVar10 + 0xc;
          if (*pcVar10 == '\x03') goto LAB_00016495;
          uVar12 = uVar12 + 1;
        } while (uVar12 < uVar5);
      }
    }
    else {
LAB_00016495:
      iVar9 = *(int *)(param_3 + 0x54);
      if (iVar9 == 0) {
        iVar9 = **(int **)(param_3 + 4);
      }
      uVar6 = uVar6 + iVar9 * (*(int **)(param_3 + 4))[1] * 4;
    }
  }
  return uVar6;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getNativeErrorCode
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(*(int *)(param_3 + 4) + 0x30);
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getCurrentLoop
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(param_3 + 0x48);
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getCurrentFrameIndex
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = *(undefined4 *)(param_3 + 0x24);
  }
  return uVar1;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 *****
Java_pl_droidsonroids_gif_GifInfoHandle_getSavedState
          (undefined4 ****param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  undefined4 *****pppppuVar2;
  int iVar3;
  int *piVar4;
  undefined4 *****pppppuVar5;
  undefined4 *****pppppuVar6;
  undefined4 *****unaff_EDI;
  int *piStack204;
  int iStack200;
  int iStack196;
  undefined4 *****pppppuStack192;
  undefined4 *****pppppuStack188;
  undefined **ppuStack184;
  undefined **ppuStack180;
  undefined4 uStack172;
  uint uStack164;
  undefined4 *****pppppuStack160;
  int *piStack156;
  longlong lStack152;
  float fStack144;
  undefined4 *****apppppuStack136 [2];
  uint uStack128;
  undefined4 ****ppppuStack120;
  undefined4 ****ppppuStack116;
  undefined4 ****ppppuStack112;
  undefined4 *****pppppuStack108;
  int iStack104;
  undefined4 uStack100;
  undefined4 *****pppppuStack96;
  undefined4 *****pppppuStack92;
  undefined **ppuStack88;
  undefined *apuStack84 [2];
  undefined4 *****pppppuStack76;
  int *piStack72;
  int *piStack68;
  undefined auStack64 [16];
  undefined4 uStack48;
  undefined4 uStack44;
  undefined4 uStack40;
  undefined4 uStack36;
  int iStack24;
  
  apuStack84[0] = &LAB_000165f1;
  iStack24 = ___stack_chk_guard;
  pppppuVar5 = (undefined4 *****)0x0;
  piVar4 = (int *)&__stack_chk_guard;
  if (param_3 != 0) {
    pppppuStack92 = (undefined4 *****)0x4;
    pppppuStack96 = (undefined4 *****)param_1;
    uStack100 = 0x16625;
    piStack68 = (int *)&__stack_chk_guard;
    unaff_EDI = (undefined4 *****)(*(code *)(*param_1)[0xb4])();
    if (unaff_EDI == (undefined4 *****)0x0) {
      ppuStack88 = (undefined **)&UNK_00017ca7;
      pppppuStack92 = (undefined4 *****)0x1;
      pppppuStack96 = (undefined4 *****)param_1;
      uStack100 = 0x166a6;
      FUN_00013760();
      piVar4 = piStack68;
    }
    else {
      auStack64 = ZEXT1216(CONCAT48(*(undefined4 *)(param_3 + 0x48),
                                    (ulonglong)*(uint *)(param_3 + 0x24))) &
                  (undefined  [16])0xffffffffffffffff;
      uStack48 = *(undefined4 *)(param_3 + 0x14);
      uStack44 = *(undefined4 *)(param_3 + 0x18);
      uStack36 = 0;
      uStack40 = *(undefined4 *)(param_3 + 0x50);
      pppppuStack96 = (undefined4 *****)auStack64;
      uStack100 = 4;
      iStack104 = 0;
      ppppuStack112 = param_1;
      ppppuStack116 = (undefined4 ****)0x1668b;
      pppppuStack108 = unaff_EDI;
      (*(code *)(*param_1)[0xd4])();
      piVar4 = piStack68;
      pppppuVar5 = unaff_EDI;
    }
  }
  if (*piVar4 == iStack24) {
    return pppppuVar5;
  }
  apuStack84[0] = (undefined *)0x166c4;
  func_0x00011af0();
  pppppuVar2 = pppppuStack76;
  ppuStack180 = (undefined **)&LAB_000166e1;
  iStack104 = ___stack_chk_guard;
  lStack152._0_4_ = (undefined4 *****)0xffffffff;
  piVar4 = (int *)&__stack_chk_guard;
  pppppuStack96 = pppppuVar5;
  pppppuStack92 = unaff_EDI;
  ppuStack88 = &__DT_PLTGOT;
  apuStack84[0] = &stack0xfffffffc;
  if (pppppuStack76[1][4] != (undefined4 ***)0x1) {
    pppppuStack192 = apppppuStack136;
    iStack196 = 4;
    iStack200 = 0;
    piStack204 = piStack68;
    piStack156 = (int *)&__stack_chk_guard;
    apuStack84[0] = &stack0xfffffffc;
    (**(code **)(*piStack72 + 0x330))(piStack72);
    lStack152._0_4_ = (undefined4 *****)0xffffffff;
    piVar4 = piStack156;
    pppppuVar5 = apppppuStack136[0];
    if ((apppppuStack136[0] <= pppppuVar2[1][4] &&
         (undefined4 *****)pppppuVar2[1][4] != apppppuStack136[0]) &&
       (pppppuVar2[0x12] < pppppuVar2[0x11] || pppppuVar2[0x12] == pppppuVar2[0x11])) {
      uStack164 = uStack128;
      pppppuVar6 = (undefined4 *****)pppppuVar2[9];
      if (apppppuStack136[0] < pppppuVar6) {
        pppppuStack192 = pppppuVar2;
        iStack196 = 0x16764;
        cVar1 = FUN_00012190();
        if (cVar1 == '\0') {
          pppppuVar2[1][0xc] = (undefined4 ***)0x3ec;
          lStack152._0_4_ = (undefined4 *****)0xffffffff;
          piVar4 = piStack156;
          goto LAB_00016860;
        }
        pppppuVar6 = (undefined4 *****)pppppuVar2[9];
      }
      pppppuVar2 = (undefined4 *****)pppppuVar2[10][(int)pppppuVar6 * 3 + 1];
      if (pppppuVar6 < apppppuStack136[0]) {
        if (pppppuVar6 == (undefined4 *****)0x0) {
          pppppuStack188 = pppppuStack76;
          pppppuStack192 = auStack64._0_4_;
          iStack196 = 0x16794;
          FUN_00013000();
          pppppuVar6 = (undefined4 *****)pppppuStack76[9];
        }
        pppppuVar5 = pppppuStack76;
        if (pppppuVar6 < apppppuStack136[0]) {
          pppppuStack160 = apppppuStack136[0];
          do {
            ppuStack184 = (undefined **)0x0;
            pppppuStack188 = (undefined4 *****)0x1;
            pppppuStack192 = pppppuVar5;
            iStack196 = 0x167bd;
            FUN_000126e0();
            pppppuStack188 = pppppuVar5;
            pppppuStack192 = auStack64._0_4_;
            iStack196 = 0x167c9;
            pppppuVar2 = (undefined4 *****)FUN_000136d0();
          } while (pppppuVar5[9] < pppppuStack160);
        }
      }
      pppppuStack76[0x12] = (undefined4 ****)(uStack164 & 0xff);
      pppppuStack76[6] = ppppuStack116;
      pppppuStack76[5] = ppppuStack120;
      pppppuStack76[0x14] = ppppuStack112;
      lStack152._0_4_ = (undefined4 *****)0xffffffff;
      piVar4 = piStack156;
      pppppuVar5 = pppppuStack76;
      if (((uint)ppppuStack120 & (uint)ppppuStack116) == 0xffffffff) {
        fStack144 = (float)((double)(ZEXT48(pppppuVar2) | 0x4330000000000000) - 4503599627370496.0)
                    * (float)ppppuStack112;
        lStack152 = (longlong)fStack144;
        ppuStack180 = (undefined **)0x1683d;
        iVar3 = FUN_000179d0();
        pppppuStack76[7] = (undefined4 ****)(iVar3 + (int)(undefined4 *****)lStack152);
        pppppuStack76[8] = (undefined4 ****)0x0;
        piVar4 = piStack156;
        pppppuVar5 = pppppuStack76;
        pppppuVar2 = (undefined4 *****)lStack152;
      }
    }
  }
LAB_00016860:
  if (*piVar4 == iStack104) {
    return (undefined4 *****)lStack152;
  }
  ppuStack180 = (undefined **)0x16877;
  func_0x00011af0();
  iStack200 = ___stack_chk_guard;
  pppppuVar6 = (undefined4 *****)0xffffffff;
  pppppuStack192 = pppppuVar5;
  pppppuStack188 = pppppuVar2;
  ppuStack184 = &__DT_PLTGOT;
  ppuStack180 = apuStack84;
  if (uStack164 != 0) {
    ppuStack180 = apuStack84;
    iVar3 = FUN_00011ec0(uStack172,(undefined4 *****)lStack152,uStack164,&piStack204);
    if (iVar3 == 0) {
      pppppuVar6 = (undefined4 *****)FUN_000166d0(uStack164,uStack172,piStack156,piStack204);
      FUN_00011fa0(uStack172,(undefined4 *****)lStack152);
    }
  }
  if (___stack_chk_guard != iStack200) {
    func_0x00011af0();
    if (iStack196 == 0) {
      pppppuVar5 = (undefined4 *****)0x0;
    }
    else {
      pppppuVar5 = *(undefined4 ******)(*(int *)(iStack196 + 0x28) + 4 + (int)pppppuStack188 * 0xc);
    }
    return pppppuVar5;
  }
  return pppppuVar6;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 ****
FUN_000166d0(undefined4 ****param_1,int *param_2,undefined4 param_3,undefined4 ****param_4)

{
  char cVar1;
  undefined4 ****ppppuVar2;
  int iVar3;
  int *piVar4;
  undefined4 ****unaff_ESI;
  undefined4 ****ppppuVar5;
  undefined4 uStack124;
  int iStack120;
  int iStack116;
  undefined4 ****ppppuStack112;
  undefined4 ****ppppuStack108;
  undefined **ppuStack104;
  undefined *puStack100;
  undefined4 uStack92;
  uint uStack84;
  undefined4 ****ppppuStack80;
  int *piStack76;
  longlong lStack72;
  float fStack64;
  undefined4 ****appppuStack56 [2];
  uint uStack48;
  undefined4 ***pppuStack40;
  undefined4 ***pppuStack36;
  undefined4 ***pppuStack32;
  int iStack24;
  
  puStack100 = &LAB_000166e1;
  iStack24 = ___stack_chk_guard;
  lStack72._0_4_ = (undefined4 ****)0xffffffff;
  piVar4 = (int *)&__stack_chk_guard;
  ppppuVar2 = param_1;
  if (param_1[1][4] != (undefined4 **)0x1) {
    ppppuStack112 = appppuStack56;
    iStack116 = 4;
    iStack120 = 0;
    uStack124 = param_3;
    piStack76 = (int *)&__stack_chk_guard;
    (**(code **)(*param_2 + 0x330))(param_2);
    lStack72._0_4_ = (undefined4 ****)0xffffffff;
    piVar4 = piStack76;
    unaff_ESI = appppuStack56[0];
    if ((appppuStack56[0] <= param_1[1][4] && (undefined4 ****)param_1[1][4] != appppuStack56[0]) &&
       (param_1[0x12] < param_1[0x11] || param_1[0x12] == param_1[0x11])) {
      uStack84 = uStack48;
      ppppuVar5 = (undefined4 ****)param_1[9];
      if (appppuStack56[0] < ppppuVar5) {
        ppppuStack112 = param_1;
        iStack116 = 0x16764;
        cVar1 = FUN_00012190();
        if (cVar1 == '\0') {
          param_1[1][0xc] = (undefined4 **)0x3ec;
          lStack72._0_4_ = (undefined4 ****)0xffffffff;
          piVar4 = piStack76;
          goto LAB_00016860;
        }
        ppppuVar5 = (undefined4 ****)param_1[9];
      }
      ppppuVar2 = (undefined4 ****)param_1[10][(int)ppppuVar5 * 3 + 1];
      if (ppppuVar5 < appppuStack56[0]) {
        if (ppppuVar5 == (undefined4 ****)0x0) {
          ppppuStack108 = param_1;
          ppppuStack112 = param_4;
          iStack116 = 0x16794;
          FUN_00013000();
          ppppuVar5 = (undefined4 ****)param_1[9];
        }
        if (ppppuVar5 < appppuStack56[0]) {
          ppppuStack80 = appppuStack56[0];
          do {
            ppuStack104 = (undefined **)0x0;
            ppppuStack108 = (undefined4 ****)0x1;
            ppppuStack112 = param_1;
            iStack116 = 0x167bd;
            FUN_000126e0();
            ppppuStack108 = param_1;
            ppppuStack112 = param_4;
            iStack116 = 0x167c9;
            ppppuVar2 = (undefined4 ****)FUN_000136d0();
          } while (param_1[9] < ppppuStack80);
        }
      }
      param_1[0x12] = (undefined4 ***)(uStack84 & 0xff);
      param_1[6] = pppuStack36;
      param_1[5] = pppuStack40;
      param_1[0x14] = pppuStack32;
      lStack72._0_4_ = (undefined4 ****)0xffffffff;
      piVar4 = piStack76;
      unaff_ESI = param_1;
      if (((uint)pppuStack40 & (uint)pppuStack36) == 0xffffffff) {
        fStack64 = (float)((double)(ZEXT48(ppppuVar2) | 0x4330000000000000) - 4503599627370496.0) *
                   (float)pppuStack32;
        lStack72 = (longlong)fStack64;
        puStack100 = (undefined *)0x1683d;
        iVar3 = FUN_000179d0();
        param_1[7] = (undefined4 ***)(iVar3 + (int)(undefined4 ****)lStack72);
        param_1[8] = (undefined4 ***)0x0;
        piVar4 = piStack76;
        ppppuVar2 = (undefined4 ****)lStack72;
      }
    }
  }
LAB_00016860:
  if (*piVar4 == iStack24) {
    return (undefined4 ****)lStack72;
  }
  puStack100 = (undefined *)0x16877;
  func_0x00011af0();
  iStack120 = ___stack_chk_guard;
  ppppuVar5 = (undefined4 ****)0xffffffff;
  ppppuStack112 = unaff_ESI;
  ppppuStack108 = ppppuVar2;
  ppuStack104 = &__DT_PLTGOT;
  puStack100 = &stack0xfffffffc;
  if (uStack84 != 0) {
    puStack100 = &stack0xfffffffc;
    iVar3 = FUN_00011ec0(uStack92,(undefined4 ****)lStack72,uStack84,&uStack124);
    if (iVar3 == 0) {
      ppppuVar5 = (undefined4 ****)FUN_000166d0(uStack84,uStack92,piStack76,uStack124);
      FUN_00011fa0(uStack92,(undefined4 ****)lStack72);
    }
  }
  if (___stack_chk_guard != iStack120) {
    func_0x00011af0();
    if (iStack116 == 0) {
      ppppuVar2 = (undefined4 ****)0x0;
    }
    else {
      ppppuVar2 = *(undefined4 *****)(*(int *)(iStack116 + 0x28) + 4 + (int)ppppuStack108 * 0xc);
    }
    return ppppuVar2;
  }
  return ppppuVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_restoreSavedState
          (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6)

{
  int iVar1;
  undefined4 uVar2;
  int unaff_EDI;
  undefined4 uStack28;
  int iStack24;
  int iStack20;
  
  iStack24 = ___stack_chk_guard;
  uVar2 = 0xffffffff;
  if (param_3 != 0) {
    iVar1 = FUN_00011ec0(param_1,param_6,param_3,&uStack28);
    if (iVar1 == 0) {
      uVar2 = FUN_000166d0(param_3,param_1,param_5,uStack28);
      FUN_00011fa0(param_1,param_6);
    }
  }
  if (___stack_chk_guard == iStack24) {
    return uVar2;
  }
  func_0x00011af0();
  if (iStack20 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = *(undefined4 *)(*(int *)(iStack20 + 0x28) + 4 + unaff_EDI * 0xc);
  }
  return uVar2;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getFrameDuration
          (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,int param_5)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(*(int *)(param_3 + 0x28) + 4 + param_5 * 0xc);
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_isOpaque(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if ((param_3 == 0) || (uVar1 = 1, *(char *)(param_3 + 0x60) == '\0')) {
    uVar1 = 0;
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getWidth(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = **(undefined4 **)(param_3 + 4);
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getHeight(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(*(int *)(param_3 + 4) + 4);
  }
  return uVar1;
}



undefined4
Java_pl_droidsonroids_gif_GifInfoHandle_getNumberOfFrames
          (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(*(int *)(param_3 + 4) + 0x10);
  }
  return uVar1;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_glTexImage2D
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
               undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  
  if ((param_3 != 0) && (iVar1 = *(int *)(param_3 + 100), iVar1 != 0)) {
    uVar2 = **(undefined4 **)(param_3 + 4);
    uVar3 = (*(undefined4 **)(param_3 + 4))[1];
    uVar4 = *(undefined4 *)(iVar1 + 8);
    func_0x00011cc0(iVar1 + 0xc);
    func_0x00011cd0(param_5,param_6,0x1908,uVar2,uVar3,0,0x1908,0x1401,uVar4);
    func_0x00011ce0(iVar1 + 0xc);
  }
  return;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_glTexSubImage2D
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
               undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  
  if ((param_3 != 0) && (iVar1 = *(int *)(param_3 + 100), iVar1 != 0)) {
    uVar2 = **(undefined4 **)(param_3 + 4);
    uVar3 = (*(undefined4 **)(param_3 + 4))[1];
    uVar4 = *(undefined4 *)(iVar1 + 8);
    func_0x00011cc0(iVar1 + 0xc);
    func_0x00011cf0(param_5,param_6,0,0,uVar2,uVar3,0x1908,0x1401,uVar4);
    func_0x00011ce0(iVar1 + 0xc);
  }
  return;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_initTexImageDescriptor
               (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  undefined *puVar6;
  
  if (param_3 == 0) {
    return;
  }
  puVar1 = (undefined4 *)func_0x00011c20(0x14);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = 0xffffffff;
    iVar3 = **(int **)(param_3 + 4);
    iVar2 = func_0x00011c20((*(int **)(param_3 + 4))[1] * iVar3 * 4);
    puVar1[2] = iVar2;
    if (iVar2 != 0) {
      *(int *)(param_3 + 0x54) = iVar3;
      *(undefined4 **)(param_3 + 100) = puVar1;
      iVar3 = func_0x00011d00(puVar1 + 3,0);
      piVar4 = (int *)func_0x00011bb0();
      *piVar4 = iVar3;
      if (iVar3 == 0) {
        return;
      }
      puVar6 = &UNK_00017cc4;
      uVar5 = 0;
      goto LAB_00016b7c;
    }
    func_0x00011b80(puVar1);
  }
  puVar6 = &UNK_00017c08;
  uVar5 = 2;
LAB_00016b7c:
  FUN_00013760(param_1,uVar5,puVar6);
  return;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_startDecoderThread
               (undefined4 param_1,undefined4 param_2,code **param_3)

{
  int iVar1;
  int *piVar2;
  undefined *puVar3;
  
  if ((param_3 != (code **)0x0) && (piVar2 = (int *)param_3[0x19], *piVar2 == -1)) {
    *(undefined2 *)(piVar2 + 1) = 1;
    iVar1 = func_0x00011c50(0,0);
    *piVar2 = iVar1;
    if (iVar1 == -1) {
      func_0x00011b80(piVar2);
      puVar3 = &UNK_00017ce8;
    }
    else {
      param_3[0x19] = (code *)piVar2;
      *param_3 = FUN_00016c40;
      iVar1 = func_0x00011d10(piVar2 + 4,0,FUN_00016d50,param_3);
      piVar2 = (int *)func_0x00011bb0();
      *piVar2 = iVar1;
      if (iVar1 == 0) {
        return;
      }
      puVar3 = &UNK_00017d01;
    }
    FUN_00013760(param_1,0,puVar3);
  }
  return;
}



void FUN_00016c40(int param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  
  piVar1 = *(int **)(param_1 + 100);
  if (*piVar1 == -1) {
    piVar3 = (int *)func_0x00011bb0();
  }
  else {
    iVar2 = func_0x00011c40(*piVar1);
    piVar3 = (int *)func_0x00011bb0();
    if ((iVar2 != 0) && (*piVar3 != 4)) {
      FUN_00013760(param_2,0,&UNK_00017d57);
    }
    iVar2 = func_0x00011d20(piVar1[4],0);
    *piVar3 = iVar2;
    if (iVar2 != 0) {
      FUN_00013760(param_2,0,&UNK_00017d6d);
    }
    *piVar1 = -1;
  }
  *(undefined4 *)(param_1 + 100) = 0;
  func_0x00011b80(piVar1[2]);
  iVar2 = func_0x00011d30(piVar1 + 3);
  *piVar3 = iVar2;
  if (iVar2 != 0) {
    FUN_00013760(param_2,0,&UNK_00017d1f);
  }
  func_0x00011b80(piVar1);
  return;
}



undefined4 FUN_00016d50(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  
  uVar2 = FUN_00016080();
  while( true ) {
    uVar3 = FUN_000179d0();
    FUN_000126e0(param_1,1,0);
    iVar1 = *(int *)(param_1 + 100);
    func_0x00011cc0(iVar1 + 0xc);
    if (*(int *)(param_1 + 0x24) == 0) {
      FUN_00013000(*(undefined4 *)(iVar1 + 8),param_1);
    }
    uVar4 = FUN_000136d0(*(undefined4 *)(iVar1 + 8),param_1);
    func_0x00011ce0(iVar1 + 0xc);
    uVar3 = FUN_000178b0(param_1,uVar3,uVar4);
    while (iVar5 = func_0x00011d40(iVar1,1,uVar3), iVar5 == -1) {
      piVar6 = (int *)func_0x00011bb0();
      if (*piVar6 != 4) goto LAB_00016e1f;
    }
    if (iVar5 < 0) break;
    if (iVar5 != 0) {
LAB_00016e37:
      FUN_000160f0();
      return 0;
    }
  }
LAB_00016e1f:
  FUN_00013760(uVar2,0,&UNK_00017d3c);
  goto LAB_00016e37;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_stopDecoderThread
               (undefined4 param_1,undefined4 param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  
  if (((param_3 != 0) && (piVar1 = *(int **)(param_3 + 100), piVar1 != (int *)0x0)) &&
     (*piVar1 != -1)) {
    iVar2 = func_0x00011c40(*piVar1);
    piVar3 = (int *)func_0x00011bb0();
    if ((iVar2 != 0) && (*piVar3 != 4)) {
      FUN_00013760(param_1,0,&UNK_00017d57);
    }
    iVar2 = func_0x00011d20(piVar1[4],0);
    *piVar3 = iVar2;
    if (iVar2 != 0) {
      FUN_00013760(param_1,0,&UNK_00017d6d);
    }
    *piVar1 = -1;
  }
  return;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_seekToFrameGL
               (undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
               undefined4 param_5)

{
  if (param_3 != 0) {
    FUN_00012250(param_3,param_5,*(undefined4 *)(*(int *)(param_3 + 100) + 8),&LAB_00016eff);
  }
  return;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_pl_droidsonroids_gif_GifInfoHandle_bindSurface
               (undefined4 param_1,undefined4 param_2,code **param_3,undefined4 param_4,
               undefined4 param_5,int param_6)

{
  int *piVar1;
  int *piVar2;
  char cVar3;
  undefined4 *puVar4;
  int iVar5;
  int *piVar6;
  undefined4 uVar7;
  int iVar8;
  int *piVar9;
  int *piVar10;
  undefined uVar11;
  undefined uVar12;
  undefined4 uVar13;
  undefined *puVar14;
  int iStack156;
  int *piStack152;
  int iStack104;
  int iStack100;
  int iStack96;
  int iStack92;
  undefined auStack88 [8];
  undefined auStack80 [8];
  code *pcStack72;
  undefined auStack64 [16];
  undefined4 uStack48;
  undefined4 uStack44;
  undefined4 uStack40;
  int iStack24;
  
  iStack24 = ___stack_chk_guard;
  piVar10 = (int *)param_3[0x19];
  if (piVar10 != (int *)0x0) {
LAB_00016f68:
    do {
      while (iVar5 = func_0x00011d40(piVar10,1,0), iVar5 == -1) {
        piVar6 = (int *)func_0x00011bb0();
        if (*piVar6 != 4) {
LAB_000171ab:
          puVar14 = &UNK_00017d3c;
          goto LAB_00016fcd;
        }
      }
      if (iVar5 == 0) {
        cVar3 = *(char *)(param_3 + 0x18);
        uVar7 = func_0x00011d70(param_1,param_5);
        puVar4 = (undefined4 *)param_3[1];
        iVar5 = func_0x00011d80(uVar7,*puVar4,puVar4[1],2 - (uint)(cVar3 == '\0'));
        if (iVar5 != 0) {
          func_0x00011d90(uVar7);
          puVar14 = &UNK_00017e28;
          goto LAB_00016fcd;
        }
        auStack64 = ZEXT816(0);
        _auStack80 = ZEXT816(0);
        uStack44 = 0;
        uStack48 = 0;
        uStack40 = 0;
        iVar5 = func_0x00011da0(uVar7,auStack80,0);
        if (iVar5 == 0) {
          iVar5 = auStack80._4_4_ * (int)pcStack72 * 4;
          param_3[0x15] = pcStack72;
          if (piVar10[2] == 0) {
            uVar12 = 1;
            if (param_6 == 0) {
              uVar11 = 0;
              piStack152 = (int *)0x0;
            }
            else {
              piStack152 = (int *)FUN_000166d0(param_3,param_1,param_6,auStack64._0_4_);
              uVar11 = 0;
              uVar12 = 1;
              if ((SBORROW4(-((int)piStack152 >> 0x1f),(uint)(piStack152 != (int *)0x0)) != false)
                  == (int)(-((int)piStack152 >> 0x1f) - (uint)(piStack152 != (int *)0x0)) < 0) {
                piStack152 = (int *)0x0;
              }
            }
          }
          else {
            func_0x00011b60(auStack64._0_4_,piVar10[2],iVar5);
            piStack152 = (int *)0x0;
            uVar11 = 1;
            uVar12 = 0;
          }
          *(undefined *)(piVar10 + 6) = uVar11;
          *(undefined *)(piVar10 + 3) = uVar12;
          param_3[6] = (code *)0xffffffff;
          param_3[5] = (code *)0xffffffff;
          func_0x00011db0(uVar7);
          if ((param_3[0x11] != (code *)0x0) && (param_3[0x12] == param_3[0x11])) {
            func_0x00011d90(uVar7);
            goto LAB_000172ca;
          }
          iVar8 = func_0x00011d10(piVar10 + 9,0,FUN_00017740,param_3);
          piVar6 = (int *)func_0x00011bb0();
          *piVar6 = iVar8;
          if (iVar8 == 0) {
            piVar1 = piVar10 + 7;
            piVar2 = piVar10 + 4;
            piVar9 = piStack152;
            goto LAB_00017384;
          }
          FUN_00013760(param_1,0,&UNK_00017d01);
        }
        func_0x00011d90(uVar7);
        goto LAB_0001713d;
      }
      if (iVar5 < 1) goto LAB_000171ab;
      while (iVar5 = func_0x00011d50(*piVar10,auStack88), iVar5 == -1) {
        piVar6 = (int *)func_0x00011bb0();
        if (*piVar6 != 4) goto LAB_00016fc4;
      }
    } while (iVar5 == 0);
LAB_00016fc4:
    puVar14 = &UNK_00017e0b;
LAB_00016fcd:
    FUN_00013760(param_1,0,puVar14);
    goto LAB_0001713d;
  }
  piVar10 = (int *)func_0x00011c20(0x28);
  if (piVar10 != (int *)0x0) {
    *(undefined2 *)(piVar10 + 1) = 1;
    iVar5 = func_0x00011c50(0,0);
    *piVar10 = iVar5;
    if (iVar5 == -1) {
      FUN_00013760(param_1,0,&UNK_00017ce8);
      func_0x00011b80(piVar10);
      goto LAB_0001713d;
    }
    iVar5 = func_0x00011d60(piVar10 + 5,0);
    piStack152 = (int *)func_0x00011bb0();
    *piStack152 = iVar5;
    if (iVar5 != 0) {
      FUN_00013760(param_1,0,&UNK_00017d87);
    }
    iVar5 = func_0x00011d60(piVar10 + 8,0);
    *piStack152 = iVar5;
    if (iVar5 != 0) {
      FUN_00013760(param_1,0,&UNK_00017db7);
    }
    iVar5 = func_0x00011d00(piVar10 + 4,0);
    *piStack152 = iVar5;
    if (iVar5 != 0) {
      FUN_00013760(param_1,0,&UNK_00017de8);
    }
    iVar5 = func_0x00011d00(piVar10 + 7,0);
    *piStack152 = iVar5;
    if (iVar5 != 0) {
      FUN_00013760(param_1,0,&UNK_00017cc4);
    }
    piVar10[2] = 0;
    param_3[0x19] = (code *)piVar10;
    *param_3 = FUN_000175f0;
    goto LAB_00016f68;
  }
  puVar14 = &UNK_00017c08;
  uVar7 = 2;
  goto LAB_00017113;
  while (piVar6 = (int *)func_0x00011bb0(), *piVar6 == 4) {
LAB_000172ca:
    iVar5 = func_0x00011d40(piVar10,1,0xffffffff);
    if (iVar5 != -1) {
      if (-1 < iVar5) goto LAB_0001713d;
      break;
    }
  }
  puVar14 = &UNK_00017e49;
  goto LAB_00017591;
  while (*piVar6 == 4) {
LAB_00017384:
    iVar8 = func_0x00011d40(piVar10,1,piVar9);
    if (iVar8 != -1) {
      piStack152 = (int *)FUN_000179d0();
      if (iVar8 < 0) goto LAB_00017518;
      if (iVar8 != 0) {
        iVar8 = piVar10[2];
        if (iVar8 == 0) {
          iVar8 = func_0x00011c20(iVar5);
          piVar10[2] = iVar8;
          if (iVar8 == 0) {
            puVar14 = &UNK_00017c08;
            uVar13 = 2;
            goto LAB_00017524;
          }
        }
        func_0x00011b60(iVar8,auStack64._0_4_,iVar5);
        goto LAB_0001752f;
      }
      iVar8 = puVar4[0xb];
      piVar9 = (int *)param_3[9];
      iStack104 = *(int *)(iVar8 + (int)piVar9 * 0x18);
      iStack100 = *(int *)(iVar8 + 4 + (int)piVar9 * 0x18);
      iStack96 = *(int *)(iVar8 + 8 + (int)piVar9 * 0x18) + iStack104;
      iStack92 = *(int *)(iVar8 + 0xc + (int)piVar9 * 0x18) + iStack100;
      uVar13 = auStack64._0_4_;
      if (piVar9 != (int *)0x0) {
        piVar9 = &iStack104;
      }
      iVar8 = func_0x00011da0(uVar7,auStack80,piVar9);
      if (iVar8 != 0) goto LAB_0001752f;
      if (param_3[9] == (code *)0x0) {
        FUN_00013000(auStack64._0_4_,param_3);
      }
      else {
        func_0x00011b60(auStack64._0_4_,uVar13,iVar5);
      }
      func_0x00011cc0(piVar1);
      cVar3 = *(char *)(piVar10 + 6);
      while (cVar3 == '\0') {
        func_0x00011dc0(piVar10 + 8,piVar1);
        cVar3 = *(char *)(piVar10 + 6);
      }
      *(undefined *)(piVar10 + 6) = 0;
      func_0x00011ce0(piVar1);
      uVar13 = FUN_000136d0(auStack64._0_4_,param_3);
      func_0x00011cc0(piVar2);
      *(undefined *)(piVar10 + 3) = 1;
      func_0x00011dd0(piVar10 + 5);
      func_0x00011ce0(piVar2);
      func_0x00011db0(uVar7);
      piVar9 = (int *)FUN_000178b0(param_3,piStack152,uVar13);
      if (-1 < (int)param_3[6]) {
        piVar9 = (int *)param_3[5];
        param_3[6] = (code *)0xffffffff;
        param_3[5] = (code *)0xffffffff;
      }
      goto LAB_00017384;
    }
  }
  FUN_000179d0();
LAB_00017518:
  puVar14 = &UNK_00017e64;
  uVar13 = 0;
  piStack152 = piVar9;
LAB_00017524:
  FUN_00013760(param_1,uVar13,puVar14);
LAB_0001752f:
  func_0x00011d90(uVar7);
  func_0x00011cc0(piVar2);
  *(undefined *)(piVar10 + 3) = 2;
  func_0x00011dd0(piVar10 + 5);
  func_0x00011ce0(piVar2);
  iVar5 = func_0x00011d20(piVar10[9],0);
  *piVar6 = iVar5;
  if (iVar5 == 0) goto LAB_0001713d;
  puVar14 = &UNK_00017e7e;
LAB_00017591:
  uVar7 = 0;
LAB_00017113:
  FUN_00013760(param_1,uVar7,puVar14);
LAB_0001713d:
  if (___stack_chk_guard == iStack24) {
    return;
  }
  func_0x00011af0();
  puVar4 = *(undefined4 **)(iStack156 + 100);
  *(undefined4 *)(iStack156 + 100) = 0;
  func_0x00011b80(puVar4[2]);
  iVar5 = func_0x00011c40(*puVar4);
  piVar10 = (int *)func_0x00011bb0();
  if ((iVar5 != 0) && (*piVar10 != 4)) {
    FUN_00013760(piStack152,0,&UNK_00017d57);
  }
  iVar5 = func_0x00011d30(puVar4 + 4);
  *piVar10 = iVar5;
  if (iVar5 != 0) {
    FUN_00013760(piStack152,0,&UNK_00017eb3);
  }
  iVar5 = func_0x00011d30(puVar4 + 7);
  *piVar10 = iVar5;
  if (iVar5 != 0) {
    FUN_00013760(piStack152,0,&UNK_00017d1f);
  }
  iVar5 = func_0x00011de0(puVar4 + 5);
  *piVar10 = iVar5;
  if (iVar5 != 0) {
    FUN_00013760(piStack152,0,&UNK_00017ecf);
  }
  iVar5 = func_0x00011de0(puVar4 + 8);
  *piVar10 = iVar5;
  if (iVar5 != 0) {
    FUN_00013760(piStack152,0,&UNK_00017eea);
  }
  func_0x00011b80(puVar4);
  return;
}



void FUN_000175f0(int param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  
  puVar1 = *(undefined4 **)(param_1 + 100);
  *(undefined4 *)(param_1 + 100) = 0;
  func_0x00011b80(puVar1[2]);
  iVar2 = func_0x00011c40(*puVar1);
  piVar3 = (int *)func_0x00011bb0();
  if ((iVar2 != 0) && (*piVar3 != 4)) {
    FUN_00013760(param_2,0,&UNK_00017d57);
  }
  iVar2 = func_0x00011d30(puVar1 + 4);
  *piVar3 = iVar2;
  if (iVar2 != 0) {
    FUN_00013760(param_2,0,&UNK_00017eb3);
  }
  iVar2 = func_0x00011d30(puVar1 + 7);
  *piVar3 = iVar2;
  if (iVar2 != 0) {
    FUN_00013760(param_2,0,&UNK_00017d1f);
  }
  iVar2 = func_0x00011de0(puVar1 + 5);
  *piVar3 = iVar2;
  if (iVar2 != 0) {
    FUN_00013760(param_2,0,&UNK_00017ecf);
  }
  iVar2 = func_0x00011de0(puVar1 + 8);
  *piVar3 = iVar2;
  if (iVar2 != 0) {
    FUN_00013760(param_2,0,&UNK_00017eea);
  }
  func_0x00011b80(puVar1);
  return;
}



undefined4 FUN_00017740(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 100);
  iVar1 = iVar2 + 0x10;
  while( true ) {
    func_0x00011cc0(iVar1);
    while (*(char *)(iVar2 + 0xc) == '\0') {
      func_0x00011dc0(iVar2 + 0x14,iVar1);
    }
    if (*(char *)(iVar2 + 0xc) == '\x02') break;
    *(undefined *)(iVar2 + 0xc) = 0;
    func_0x00011ce0(iVar1);
    FUN_000126e0(param_1,1,0);
    func_0x00011cc0(iVar2 + 0x1c);
    *(undefined *)(iVar2 + 0x18) = 1;
    func_0x00011dd0(iVar2 + 0x20);
    func_0x00011ce0(iVar2 + 0x1c);
  }
  func_0x00011ce0(iVar1);
  FUN_000160f0();
  return 0;
}



void Java_pl_droidsonroids_gif_GifInfoHandle_postUnbindSurface
               (undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  
  if ((param_3 != 0) && (puVar1 = *(undefined4 **)(param_3 + 100), puVar1 != (undefined4 *)0x0)) {
    do {
      iVar2 = func_0x00011df0(*puVar1,1,0);
      if (iVar2 != -1) {
        if (iVar2 == 0) {
          return;
        }
        piVar3 = (int *)func_0x00011bb0();
        if (*piVar3 == 9) {
          return;
        }
        goto LAB_00017889;
      }
      piVar3 = (int *)func_0x00011bb0();
    } while (*piVar3 == 4);
    if (*piVar3 != 9) {
LAB_00017889:
      FUN_00013760(param_1,0,&UNK_00017e97);
    }
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_000178b0(uint param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iStack96;
  int iStack92;
  int iStack84;
  undefined4 uStack80;
  int *piStack76;
  undefined **ppuStack72;
  undefined *puStack68;
  int iStack64;
  undefined **ppuStack60;
  uint uStack56;
  int *piStack52;
  undefined8 uStack48;
  float fStack40;
  int iStack32;
  int iStack28;
  int iStack24;
  
  puStack68 = &LAB_000178c1;
  ppuStack60 = &__DT_PLTGOT;
  piVar3 = (int *)&__stack_chk_guard;
  iStack24 = ___stack_chk_guard;
  if (param_3 == 0) {
    uVar1 = 0xffffffff;
    iVar4 = -1;
    param_1 = param_3;
  }
  else {
    if (*(float *)(param_1 + 0x50) == 1.0) {
      iStack64 = 0;
      uStack48._0_4_ = param_3;
    }
    else {
      fStack40 = (float)((double)((ulonglong)param_3 | 0x4330000000000000) - 4503599627370496.0) /
                 *(float *)(param_1 + 0x50);
      uStack48 = (longlong)fStack40;
      uStack48._4_4_ = (int)((ulonglong)uStack48 >> 0x20);
      iStack64 = uStack48._4_4_;
    }
    piStack76 = &iStack32;
    uStack80 = 4;
    iStack84 = 0x1795b;
    uStack56 = (uint)uStack48;
    piStack52 = piVar3;
    func_0x00011cb0();
    uVar2 = (iStack32 * 1000 - param_2) + iStack28 / 1000000;
    iVar5 = (int)uVar2 >> 0x1f;
    uVar1 = (uint)uStack48 - uVar2;
    iVar4 = (iStack64 - iVar5) - (uint)((uint)uStack48 < uVar2);
    if ((SBORROW4(iVar5,iStack64) != SBORROW4(iVar5 - iStack64,(uint)(uVar2 < uStack56))) ==
        (int)((iVar5 - iStack64) - (uint)(uVar2 < uStack56)) < 0) {
      iVar4 = 0;
      uVar1 = 0;
    }
    *(uint *)(param_1 + 0x1c) = param_2 + uVar1;
    *(uint *)(param_1 + 0x20) = ((int)param_2 >> 0x1f) + iVar4 + (uint)CARRY4(param_2,uVar1);
    piVar3 = piStack52;
  }
  ppuStack72 = ppuStack60;
  if (*piVar3 != iStack24) {
    puStack68 = (undefined *)0x179cf;
    func_0x00011af0();
    iStack84 = ___stack_chk_guard;
    piStack76 = (int *)param_1;
    puStack68 = &stack0xfffffffc;
    func_0x00011cb0(4,&iStack96);
    if (___stack_chk_guard != iStack84) {
      func_0x00011af0();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar4 = iStack92 / 1000000 + iStack96 * 1000;
    return CONCAT44(iVar4,iVar4);
  }
  return CONCAT44(iVar4,uVar1);
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_000179d0(void)

{
  int iStack32;
  int iStack28;
  int iStack20;
  
  iStack20 = ___stack_chk_guard;
  func_0x00011cb0(4,&iStack32);
  if (___stack_chk_guard == iStack20) {
    return iStack28 / 1000000 + iStack32 * 1000;
  }
  func_0x00011af0();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


