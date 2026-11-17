# Spend control for live measurements

Two tracks measure real models. They answer different questions and are
never merged into one number.

| | API track | Claude Code track |
|---|---|---|
| Question | how a model with identical, controlled tools behaves in arms A to D | how the real Claude Code agent behaves with the same simulated tools |
| Billing | per token, hard cap enforced in code | the maintainer's subscription, usage-limit windows |
| Models | the cheapest model that fits the cap | whatever the plan offers, per run |
| Comparable across arms | yes | within the track only |
| Runs | the maintainer's machine, opt-in `--live` | the maintainer's machine only |
| CI | never | never |

## API track: a hard cap, enforced in code

The cap is code, not a promise (`asl/budget.go`):

- One ledger file for the whole lab. The total is chosen by the person who creates the ledger (`--budget-usd` on the first live run) and is kept only in that file, which stays on their machine and is ignored by git. No amount is a constant of the code, and public reports never contain spend or budget figures.
- Before every request the worst case (input tokens plus the full `max_tokens`) is reserved. A request that could take the lab over a cap is not sent, and the episode is recorded INVALID.
- Caps are derived from the total: most of it is usable by one run and a small share by one episode, and the rest is kept back for reruns after a harness bug.
- A call whose outcome is unknown (timeout, dropped connection) stays counted as spent. A call that was provably never sent costs nothing.
- Prices are pinned in code with their date; a model without a pinned price cannot be used.
- Input tokens are counted with the token counting endpoint, which is free, so reservations are exact on input.
- Raising a cap means editing the ledger file by hand, never a flag.

Order of spend: a small pilot first to measure the real cost per episode, then the full matrix. The cheapest model fits a full run of the corpus many times over; a stronger model costs roughly an order of magnitude more per episode.

## Claude Code track: no dollar cap, a usage cap

Subscription limits are windows, so the runner checkpoints after every
episode, stops cleanly at a limit and resumes later. The report shows
episodes, models, Claude Code version, durations and limit interruptions. It
does not claim a cost.

This track needs the subscription terms to allow scripted, unattended use.
That is the maintainer's check before the first run.

## Getting and storing the API key

The Claude Code subscription does not include API credit, so the API track
needs an API key with a small prepaid balance.

1. Sign in at https://platform.claude.com (the Console; it is a separate login from claude.ai).
2. Billing: add a small prepaid balance and leave auto-reload off. The balance is a second cap, behind the one in code.
3. Settings, API keys, Create key. Name it `pandaward-lab` and copy it when it is shown; it is not shown again.
4. Open a new PowerShell window and run these lines. The key is typed hidden, is not saved in shell history and goes to one file only you can read:

   ```powershell
   $k = Read-Host "Paste the Anthropic API key (nothing will show)" -AsSecureString
   $dir = "$HOME\.pandaward-lab"
   New-Item -ItemType Directory -Force $dir | Out-Null
   [System.IO.File]::WriteAllText("$dir\anthropic.key", [System.Net.NetworkCredential]::new("", $k).Password)
   icacls "$dir\anthropic.key" /inheritance:r /grant:r "${env:USERNAME}:(R,W)" | Out-Null
   Remove-Variable k
   ```

5. `pandaward lab run --provider api --live --budget-usd N` reads the key from that file when `ANTHROPIC_API_KEY` is not set (or from `--key-file`), and creates the ledger with the total `N` the first time. The key is never printed, logged or written to a run artifact.
6. When the measurements are done, delete the key in the Console (Settings, API keys) and remove `~/.pandaward-lab/anthropic.key`.

The file lives outside the repository. Never paste the key into a command line, an issue or a chat.
