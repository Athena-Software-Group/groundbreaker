"""How the money comes back: the plain route on top of the To do tab.

Tracing and freezing are not recovery. A freeze only stops funds moving; an issuer or exchange gives them up to an
authority, never to the person asking, and a court then decides who gets them. So this module says, in plain words,
where the loss stands in three buckets (frozen, still sitting in wallets, gone or pooled) and which steps turn a frozen
balance into money returned. The steps are tasks of the To do list (source `route`, app.domain.todo._route), so a person
ticks them off there. The route is the usual one, not legal advice: the wording says who does each step and leaves the
legal instrument to the case's lawyer.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import FreezeCheck
from app.freeze import native
from app.providers.prices import to_usd

MIN_PARKED = Decimal("0.01")  # a watched wallet with less than this holds dust, not funds


@dataclass(frozen=True)
class Step:
    key: str
    title: str
    why: str
    who: str


def holder(db: Session, case: Any) -> str | None:
    """The issuer that froze the case's funds on-chain, if one did."""
    return db.scalar(select(FreezeCheck.issuer).where(FreezeCheck.case_id == case.id, FreezeCheck.blacklisted.is_(True),
                                                      FreezeCheck.status == "ok").order_by(FreezeCheck.id.desc()).limit(1))


def steps(name: str | None) -> list[Step]:
    """The route from a frozen balance to money returned. `name`: who holds it (None: the service holding the funds)."""
    who = name or "the service holding the funds"
    return [
        Step("evidence", "Give the police the proof",
             "Send the officer on the case the chain of transfers from your loss to the frozen funds. A police report "
             "alone does not show that these funds are yours.", "You"),
        Step("issuer", f"Get law enforcement to contact {who}",
             f"{who[0].upper()}{who[1:]} acts for law enforcement, not for the person asking: your own request cannot "
             "release the funds. Ask the officer to write to them, and to tell you when they have.", "Police"),
        Step("seizure", "Get a seizure order",
             "A prosecutor or court orders the funds seized. Your lawyer asks for this. A provider abroad can need a "
             "cross-border request, which takes longer.", "Your lawyer and the prosecutor"),
        Step("return", "Get the funds returned to you",
             "The funds move to a wallet the order names, and the court decides who receives them. Expect months. Ask "
             "your lawyer what you must file to be recognised as the injured party.", "The court"),
    ]


def position(db: Session, case: Any, frozen: float) -> dict:
    """The loss in three buckets, in USD. `parked`: funds still sitting in watched wallets, which nobody can freeze."""
    loss = float(case.loss_usd or 0)
    wallets = [r for r in native.view(db, case) if r["balance"] is not None and r["balance"] >= MIN_PARKED]
    parked = sum(float(to_usd(r["symbol"], r["balance"]) or 0) for r in wallets)
    return {"loss": loss, "frozen": frozen, "parked": parked, "wallets": len(wallets),
            "elsewhere": max(0.0, loss - frozen - parked)}


def view(db: Session, case: Any, tasks: list) -> dict:
    """The To do tab's panel. A step is done when its task is; the first one not done is the next one. The route's tasks
    carry the frozen amount (app.domain.todo._route), and there are none while nothing is frozen."""
    from app.domain import todo

    pos = position(db, case, max((t.value or 0 for t in tasks if t.source == todo.ROUTE), default=0.0))
    route = []
    waiting = True
    for s in steps(holder(db, case)):
        task = todo.find(tasks, f"{todo.ROUTE}:{s.key}")
        done = task is not None and task.status == todo.DONE
        route.append({"title": s.title, "why": s.why, "who": s.who, "done": done, "next": waiting and not done})
        waiting = waiting and done
    return {**pos, "steps": route if pos["frozen"] > 0 else []}
