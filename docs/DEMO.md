# Recording the demo GIF

The README's 15-second demo GIF has to be recorded on a machine with a terminal
(it can't be produced headlessly). Here is a repeatable way to make it.

## Option A — terminal GIF (CLI)

The cleanest 15 seconds: one engagement, start to report.

1. Install a recorder:
   - [`terminalizer`](https://github.com/faressoft/terminalizer): `npm i -g terminalizer`
   - or [`asciinema`](https://asciinema.org) + [`agg`](https://github.com/asciinema/agg) to convert a cast to GIF.

2. Record this exact sequence (it runs in well under 15s):

   ```bash
   terminalizer record arena-demo -d 0
   # in the recording shell:
   arena run --scenario shop-01 --red scripted --blue scripted --seed 42
   exit
   terminalizer render arena-demo -o docs/demo.gif
   ```

   Or with asciinema:

   ```bash
   asciinema rec arena-demo.cast -c "arena run --scenario shop-01 --seed 42"
   agg arena-demo.cast docs/demo.gif
   ```

3. Reference it at the top of `README.md`:

   ```markdown
   ![Sentinel Arena demo](docs/demo.gif)
   ```

## Option B — arena UI capture (frontend)

For a flashier GIF of the live split-screen:

```bash
# terminal 1
uv pip install -e ".[api]"
uvicorn sentinel_arena.api.server:app

# terminal 2
cd web && npm install && npm run dev
```

Open http://localhost:3000, press **Run engagement**, and screen-record the
split-screen red/blue feed + network graph with any screen recorder (e.g.
ScreenToGif on Windows, Kap on macOS, Peek on Linux). Trim to ~15s and save to
`docs/demo.gif`.

> The GIF is intentionally not committed as a binary by the build steps above —
> record it locally and add it so the README opens with motion.
