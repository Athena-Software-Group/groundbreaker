# To do: the case's consolidated task list

One list of everything that should be done for a case, with a priority and a due date. It is the case page's
**To do** tab, right after Overview (its badge counts the open P1 tasks). The Overview has a To do card: a table of the
top eight open tasks, overdue first (priority, task and why, due date, source, assignee, and the task's one-click
action), linking to the full tab. The AI Assistant (Pythia) has a `/todo` skill. The code lives in `app/domain/todo.py`, the routes in
`app/web/routes_todo.py`, and the state in the `case_tasks` table (migration 0012).

## Where the tasks come from

Aegis derives most tasks from the case each time the list is read. Nothing is stored for a derived task until a
person acts on it. Each derived task has a stable source key, a one-line reason, a due date taken from its source
clock (or none), and one action. The action is the source page's own step (a link, or a form posted to an existing
route), so the To do list never drafts, sends or confirms anything itself.

| Source | Tasks |
|---|---|
| Freeze & stop-order board | every row under "Act now" and "Frozen — confirm or claim it" (send a draft, chase an overdue reply, an LE hand-off, add the officer's contact, confirm a hold or freeze); rows on the LE / court route that have a step to take; duplicate and pointless drafts to discard |
| Recovery plan | moves that no provider row covers: identify wallet owners, re-trace, funds-left alerts, watch-list moves, funds that just arrived |
| Block status | rows the board does not cover (letters to LE and counsel, Outlook e-mails to review): replies to read or confirm, overdue replies; path clocks falling due within 14 days or passed within the last 3 (a submit-by date, a playbook clock, the expiry of a confirmed hold) |
| Mailbox | inbound mail matched to the case and waiting for triage; the unassigned queue (system admins only); old Outlook checklists to retire or record as sent |
| Evidence | type suggestions nobody has confirmed yet; evidence the next moves still lack |
| Case setup | no trace yet; no sender profile; a sender profile whose instrument has no authority document; an LE contact with no officer or e-mail; optional consents that are off (owner lookups, AI reads evidence, AI reads mailbox replies) |
| Manual | tasks people add themselves (title, priority, due date, assignee, note) |

The sender-profile check reads: *"Sign the Letter of Authorisation and attach it as the sender profile's authority
document"*, with the profile's own instrument name in place of "Letter of Authorisation". An unsigned draft can exist
outside Aegis; this task stays open until a signed copy is uploaded under Evidence → Legal and ticked on the Sender
profile.

## Priority

The priority is derived from the task; a person can override it. The constants are in `app/domain/todo.py`.

* **P1**: overdue, due within 48 hours (`P1_DUE`), or at least $10,000 at stake (`P1_MONEY_USD`) with urgency. Urgency
  means a Recovery plan urgency of 2 or more (`URGENT`), a frozen balance to claim, a target nobody has asked yet, a
  reply to confirm, or an LE hand-off that is due.
* **P2**: due within 7 days (`P2_DUE`), or at least $50 at stake (`MONEY_USD`).
* **P3**: everything else (setup and optional tasks).

Some sources never go below P2: board rows under "Act now", duplicate or pointless drafts (they could still be
e-mailed), mail waiting for triage, old Outlook checklists, and the missing authority document.

The list is sorted overdue first, then by priority, then by due date (tasks without one last).

## State

A person can mark a task done, snooze it for 1, 3 or 7 days, dismiss it with a note, or edit its priority, due date
and assignee. For a manual task the title and note can be edited too.

For a derived task, the row also keeps a fingerprint of what its source said at the time. A derived task that is
done, dismissed or snoozed stays hidden until one of two things happens: the snooze runs out, or the source changes
materially (a new fingerprint), which reopens it. When the source no longer calls for the task, Aegis closes it as
**done (resolved)**, with no `done_by`. It never does this while that source could not be read. "Done recently"
lists the last 14 days.

The fingerprint is built only from the source's own state: a target's status, its step kind and the request its
status comes from, the plan move's kind and its own primary action, a reply's status. It never includes an action
label or anything that depends on the viewer being allowed to Send, build the pack or see prepared e-mails, so a
task one member dismissed stays dismissed when a member with another role opens the list.

The automatic changes (reopened or resolved) are written when the To do tab or the Overview card is read, and get no
audit row. Only a viewer who sees the task's whole source makes them: investigators and up, and case admins for the
evidence the next moves lack (it reads the Financial folder too). A read-only member's view writes nothing and shows
the state a person set. A stored task that the viewer could not have derived is neither shown to them nor closed by
their view. That covers a sensitive Recovery plan move below `view_restricted` (the row keeps a `sensitive` flag),
the unassigned mail queue for anyone but a system admin, and an evidence item the viewer may not see. Every change a person makes is audited (`CREATE` / `UPDATE` on `case_tasks`), with ids, the operation, the
source and the names of the fields that changed. The audit never records a title, a note, or a key that may contain
a wallet address.

## Who sees what

* **External members** see nothing: the tab, the API and the routes all need the read-only role.
* **Read-only members** see the list but no buttons.
* **Investigators and up** can act on tasks. Each task's action button also needs that action's own permission
  (Send, discard and the sender profile are for case admins).

Contact details and complaint references are masked below `manage_le_contacts`, as on the Authorities tab. A person's
free-text owner name is masked below `view_restricted`. Recovery plan moves built from reply content are left out
below `view_restricted`, as on the plan itself.

The `/todo` skill never quotes the reason line or a manual task's title (free text), and leaves out tasks built from
reply content unless "AI reads mailbox replies" is on.

## Cost

Building the list reads each source once: the board, the plan the board was built from, its block rows, two mailbox
queries, the case's evidence items, the sender profile, and one `case_tasks` query.

* The Overview builds the list inside the same block-rows pass as its Block status and Recovery plan cards, and the
  badge reads from that pass too.
* On the Authorities tab, the badge reuses the tab's own board.
* On other pages, the badge shows the count from the last build if it is less than 60 seconds old (`BADGE_TTL`, per
  process). Otherwise it builds the list once, and writes nothing.
