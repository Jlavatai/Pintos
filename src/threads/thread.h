#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <hash.h>
#include <stdint.h>
#include "synch.h"

#include "threads/fixed-point.h"
#include "userprog/process.h"

#define MAX(A, B) (A > B ? A : B)

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING,       /* About to be destroyed. */
    THREAD_SLEEP        /* Sleeping thread. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    struct list lock_list;              /* Ordered List of the thread's held locks, with highest priority first */
    int priority;
    struct lock *blocker;               /* Each thread knows of the lock that's blocking it*/

    long long wakeup_tick;              /* If sleeping, the tick we want to wake up on. */

    struct list_elem allelem;           /* List element for all threads list. */
    int nice;                            /* The nice value used for the mlfq scheduler. */
    fixed_point recent_cpu;              /* The recent CPU value used by the mlfq scheduler. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */    


#ifdef USERPROG
    struct file * file;                  /* A pointer to the struct holding the executing file this thread's code is contained in */
    struct proc_information * proc_info; /* A pointer to the parent's information struct containing information on this child */
    struct list children;                /* Holds the list of processes started by this process. */
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
#endif

#ifdef VM
    struct lock supplemental_page_table_lock; /* Prevents race conditions for access of supplemental page table */              
    struct hash supplemental_page_table;
    struct hash mmap_table;
    int next_mmapid;
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };


/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);
tid_t user_thread_create (const char *name, int priority, thread_func *, void *, struct thread *);

void thread_block (void);
void thread_unblock (struct thread *);


struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);
void thread_sleep (int);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);
void thread_foreachinlist (struct list * thread_list, thread_action_func *func, void *aux);

void thread_sleep_ticker (void);

int thread_get_priority (void);
int thread_explicit_get_priority (struct thread *);

void thread_set_priority (int);

void thread_donate_priority_lock(struct thread *, struct lock *);
void thread_donate_priority_lock_rec(struct thread *, struct lock *);
void thread_restore_priority_lock(struct lock *);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

struct thread* thread_lookup(tid_t tid);

void thread_set_parent(struct thread *);

bool has_higher_priority(const struct list_elem *, const struct list_elem *, void *);

#endif /* threads/thread.h */
