# Budget for live measurements

Two tracks measure real models. They answer different questions and are
never merged into one number.

| | API track | Claude Code track (ASL-10) |
|---|---|---|
| Question | how a model with identical, controlled tools behaves in arms A to D | how the real Claude Code agent behaves with the same simulated tools |
| Billing | per token, hard cap in code | the maintainer's subscription, usage-limit windows |
| Models | cheapest model that fits the cap | whatever the plan offers, per run |
| Comparable across arms | yes | within the track only |
| Runs | maintainer's machine, opt-in `--live` | maintainer's machine only |
| CI | never | never |

## API track: total cap $5

The cap is code, not a promise (`asl/budget.go`):

- One ledger file for the whole lab. The cap is fixed when the ledger is created; raising it means editing that file by hand.
- Before every request the worst case (input tokens plus the full `max_tokens`) is reserved. A request that could take the lab over a cap is not sent, and the episode is recorded INVALID.
- Caps: $5.00 in total, $3.50 for one run, $0.05 for one episode. The remaining $1.50 is kept for reruns after a harness bug.
- A call whose outcome is unknown (timeout, dropped connection) stays counted as spent. A call that was provably never sent costs nothing.
- Prices are pinned in code with their date; a model without a pinned price cannot be used.
- Input tokens are counted with the token counting endpoint, which is free, so reservations are exact on input.

Planned T1 matrix: 20 scenarios x 3 repetitions x 4 arms = 240 episodes, 12
turns each, on `claude-haiku-5-5` ($0.10 and $0.50 per million tokens, higher
above 100K tokens). The estimate is $2.72 of the $5 (a test fails if the plan
stops fitting). A stronger model does not fit: the same matrix on a Sonnet
would cost about 20 times as much.

Order of spend: a 12-episode pilot first to measure the real cost per episode,
then T1. The report shows real spend per run and model from the ledger, not
the estimate.

## Claude Code track: no dollar cap, a usage cap

Subscription limits are windows, so the runner checkpoints after every
episode, stops cleanly at a limit and resumes later. The report shows
episodes, models, Claude Code version, durations and limit interruptions. It
does not claim a cost.

This track needs the subscription terms to allow scripted, unattended use.
That is the maintainer's check before the first run; until then it stays
mock-only.
