--------------------------- MODULE AuditJournal ---------------------------
(***************************************************************************)
(* Concurrent launches choosing an audit journal.                          *)
(*                                                                         *)
(* Code: src/audit/jsonl_sink.cpp (make_jsonl_sink) and                    *)
(* src/run/audit_journal.cpp (open_default_audit_journal,                  *)
(* remove_old_overflow_journals).                                          *)
(*                                                                         *)
(* A launch first tries the shared journal.  If another launch holds its   *)
(* lock, the launch runs a retention pass over the per-launch journals and *)
(* then creates one of its own.  Opening a journal is three system calls   *)
(* that other launches can interleave with: open(O_CREAT), fstat, flock.   *)
(* The retention pass is three as well: open, flock, unlink.               *)
(*                                                                         *)
(* Abstractions, each of which only adds behaviors:                        *)
(*   - The retention pass may pick any per-launch journal, not only the    *)
(*     oldest ones beyond the cap.                                         *)
(*   - A launch may exit at any time once it is writing.                   *)
(* Assumption: per-launch names are never reused (they are 64 random       *)
(* bits), so a file is identified with its name.                           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Launches,          \* the concurrent launches
    MaxFiles,          \* bound on per-launch journals ever created
    RecheckAfterLock   \* TRUE: the sink checks the file is still named
                       \* after it takes the lock (the fix)

ASSUME MaxFiles \in Nat /\ RecheckAfterLock \in BOOLEAN

None   == 0
Shared == MaxFiles + 1
Files  == 1..MaxFiles

VARIABLES
    pc,          \* [Launches -> control state]
    sharedLock,  \* launch holding the shared journal's lock, or None
    linked,      \* [Files -> BOOLEAN]: the file has a name in the directory
    lock,        \* [Files -> Launches \cup {None}]: flock holder
    own,         \* [Launches -> Files \cup {None, Shared}]: journal being opened or written
    ret,         \* [Launches -> Files \cup {None}]: file the retention pass has open
    retLocked,   \* [Launches -> BOOLEAN]: the retention pass holds that file's lock
    created      \* number of per-launch journals created so far

vars == <<pc, sharedLock, linked, lock, own, ret, retLocked, created>>

States == {"start", "retain", "create", "opened", "statted", "recheck",
           "writing", "done", "failed"}

TypeOK ==
    /\ pc \in [Launches -> States]
    /\ sharedLock \in Launches \cup {None}
    /\ linked \in [Files -> BOOLEAN]
    /\ lock \in [Files -> Launches \cup {None}]
    /\ own \in [Launches -> Files \cup {None, Shared}]
    /\ ret \in [Launches -> Files \cup {None}]
    /\ retLocked \in [Launches -> BOOLEAN]
    /\ created \in 0..MaxFiles

Init ==
    /\ pc = [l \in Launches |-> "start"]
    /\ sharedLock = None
    /\ linked = [f \in Files |-> FALSE]
    /\ lock = [f \in Files |-> None]
    /\ own = [l \in Launches |-> None]
    /\ ret = [l \in Launches |-> None]
    /\ retLocked = [l \in Launches |-> FALSE]
    /\ created = 0

(* make_jsonl_sink on the shared path.  The shared journal is never        *)
(* unlinked, so its open, fstat and flock are one step.                    *)
TryShared(l) ==
    /\ pc[l] = "start"
    /\ IF sharedLock = None
          THEN /\ sharedLock' = l
               /\ own' = [own EXCEPT ![l] = Shared]
               /\ pc' = [pc EXCEPT ![l] = "writing"]
          ELSE /\ pc' = [pc EXCEPT ![l] = "retain"]
               /\ UNCHANGED <<sharedLock, own>>
    /\ UNCHANGED <<linked, lock, ret, retLocked, created>>

(* remove_old_overflow_journals: openat + fstat of one candidate.          *)
RetainOpen(l, f) ==
    /\ pc[l] = "retain" /\ ret[l] = None
    /\ linked[f]
    /\ ret' = [ret EXCEPT ![l] = f]
    /\ UNCHANGED <<pc, sharedLock, linked, lock, own, retLocked, created>>

(* flock(LOCK_EX | LOCK_NB); a held lock skips the candidate.              *)
RetainLock(l) ==
    /\ pc[l] = "retain" /\ ret[l] # None /\ ~retLocked[l]
    /\ IF lock[ret[l]] = None
          THEN /\ lock' = [lock EXCEPT ![ret[l]] = l]
               /\ retLocked' = [retLocked EXCEPT ![l] = TRUE]
               /\ UNCHANGED ret
          ELSE /\ ret' = [ret EXCEPT ![l] = None]
               /\ UNCHANGED <<lock, retLocked>>
    /\ UNCHANGED <<pc, sharedLock, linked, own, created>>

(* unlinkat, then the descriptor closes and the lock is released.          *)
RetainUnlink(l) ==
    /\ pc[l] = "retain" /\ retLocked[l]
    /\ linked' = [linked EXCEPT ![ret[l]] = FALSE]
    /\ lock' = [lock EXCEPT ![ret[l]] = None]
    /\ ret' = [ret EXCEPT ![l] = None]
    /\ retLocked' = [retLocked EXCEPT ![l] = FALSE]
    /\ UNCHANGED <<pc, sharedLock, own, created>>

RetainDone(l) ==
    /\ pc[l] = "retain" /\ ret[l] = None
    /\ pc' = [pc EXCEPT ![l] = "create"]
    /\ UNCHANGED <<sharedLock, linked, lock, own, ret, retLocked, created>>

(* open(O_CREAT) on a fresh per-launch name.                               *)
Create(l) ==
    /\ pc[l] = "create"
    /\ created < MaxFiles
    /\ created' = created + 1
    /\ linked' = [linked EXCEPT ![created + 1] = TRUE]
    /\ own' = [own EXCEPT ![l] = created + 1]
    /\ pc' = [pc EXCEPT ![l] = "opened"]
    /\ UNCHANGED <<sharedLock, lock, ret, retLocked>>

(* fstat: st_nlink must be 1.  With the fix a file that lost its name is   *)
(* reported as replaced and the launch draws another name; without it the  *)
(* launch fails.                                                           *)
Stat(l) ==
    /\ pc[l] = "opened"
    /\ IF linked[own[l]]
          THEN /\ pc' = [pc EXCEPT ![l] = "statted"]
               /\ UNCHANGED own
          ELSE /\ pc' = [pc EXCEPT ![l] = IF RecheckAfterLock THEN "create" ELSE "failed"]
               /\ own' = [own EXCEPT ![l] = None]
    /\ UNCHANGED <<sharedLock, linked, lock, ret, retLocked, created>>

(* flock(LOCK_EX | LOCK_NB); busy draws another name.                      *)
Lock(l) ==
    /\ pc[l] = "statted"
    /\ IF lock[own[l]] = None
          THEN /\ lock' = [lock EXCEPT ![own[l]] = l]
               /\ pc' = [pc EXCEPT ![l] = IF RecheckAfterLock THEN "recheck" ELSE "writing"]
               /\ UNCHANGED own
          ELSE /\ pc' = [pc EXCEPT ![l] = "create"]
               /\ own' = [own EXCEPT ![l] = None]
               /\ UNCHANGED lock
    /\ UNCHANGED <<sharedLock, linked, ret, retLocked, created>>

(* The fix: fstat again under the lock.                                    *)
Recheck(l) ==
    /\ pc[l] = "recheck"
    /\ IF linked[own[l]]
          THEN /\ pc' = [pc EXCEPT ![l] = "writing"]
               /\ UNCHANGED <<lock, own>>
          ELSE /\ lock' = [lock EXCEPT ![own[l]] = None]
               /\ own' = [own EXCEPT ![l] = None]
               /\ pc' = [pc EXCEPT ![l] = "create"]
    /\ UNCHANGED <<sharedLock, linked, ret, retLocked, created>>

Exit(l) ==
    /\ pc[l] = "writing"
    /\ IF own[l] = Shared
          THEN /\ sharedLock' = None
               /\ UNCHANGED lock
          ELSE /\ lock' = [lock EXCEPT ![own[l]] = None]
               /\ UNCHANGED sharedLock
    /\ own' = [own EXCEPT ![l] = None]
    /\ pc' = [pc EXCEPT ![l] = "done"]
    /\ UNCHANGED <<linked, ret, retLocked, created>>

Next ==
    \E l \in Launches :
        \/ TryShared(l)
        \/ \E f \in Files : RetainOpen(l, f)
        \/ RetainLock(l)
        \/ RetainUnlink(l)
        \/ RetainDone(l)
        \/ Create(l)
        \/ Stat(l)
        \/ Lock(l)
        \/ Recheck(l)
        \/ Exit(l)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* A launch that is recording writes to a file that has a name.  Records   *)
(* written to an unlinked file are lost when the launch exits.             *)
WriterIsNamed ==
    \A l \in Launches :
        (pc[l] = "writing" /\ own[l] # Shared) => linked[own[l]]

(* No two launches record to the same journal.                             *)
SingleWriter ==
    \A a, b \in Launches :
        (a # b /\ pc[a] = "writing" /\ pc[b] = "writing") => own[a] # own[b]

(* Retention never makes a launch fail to open its journal.                *)
NoSpuriousFailure ==
    \A l \in Launches : pc[l] # "failed"

(* A journal a launch is recording to is locked by that launch.            *)
WriterHoldsLock ==
    \A l \in Launches :
        pc[l] = "writing" =>
            IF own[l] = Shared THEN sharedLock = l ELSE lock[own[l]] = l
===========================================================================
