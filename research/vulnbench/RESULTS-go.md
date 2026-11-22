# Go front end on Snyk VulnBench 2.0 (issue #534)

The first run in [RESULTS.md](RESULTS.md) stays as published: PandaWard at the tagged commit `vulnbench2-freeze`, 55 of 108 references located, Go 9 of 32. This is the same suite and the same matching rule, run again with the Go front end for the taint engine (`internal/taint/golang`, `rules/taint/go.yaml`), built-in configuration only, on 18 November 2026.

## How the Go front end was developed

It was written and tested against small programs of its own (the unit tests), against the Contrast `go-test-bench` (whose handlers take their input from a framework wrapper, so it found almost nothing) and against two clean projects, chi and echo. The VulnBench Go projects were not read and not scanned while the front end and the specification were written. The specification names sinks and sources of the standard library and of gin, echo, fiber, chi and gorilla/mux, written from knowledge of those libraries. The author knew the list of weakness classes in the suite and the counts per language from the protocol, not the code.

## Run A, before any change made after looking at this suite

| | located | same weakness | Go located |
|---|---|---|---|
| first run (tag `vulnbench2-freeze`) | 55 of 108 | 51 | 9 of 32 |
| with the Go front end | 75 of 108 (69%, 95% interval 60% to 77%) | 71 | 29 of 32 (91%, 76% to 97%) |

The other languages are unchanged (Python 27 of 34, JavaScript and TypeScript 11 of 30, Java 8 of 12). Per reference: `go-first-builtin-refs.csv`. The Go front end reported 18 high or critical Go taint findings that match no reference (`go-first-builtin-unmatched.csv`).

## Run B, after reading those 18 findings

Reading the 18 unmatched Go findings showed three causes, each a defect of the specification and not of this suite: environment variables and command line arguments (`os.Getenv`, `os.Args`) were sources, which the operator chooses and an attacker does not; `url.URL.String` and `EscapedPath` were sources for every URL, including a database URL from a configuration; and the `template.New(x)` shape of template injection was wrong (the sink is `Parse`). The first two were removed; the third was corrected and now finds the template injection that run A missed. These changes were made after reading this suite's findings, so run B is no longer a held-out measurement: its recall is shown, and the figure to quote as independent is run A.

| | located | same weakness | Go located | unmatched Go taint findings |
|---|---|---|---|---|
| run B | 77 of 108 (71%, 62% to 79%) | 73 | 31 of 32 (97%, 84% to 99%) | 6 |

The two references gained over run A are the two template injections, written after reading the class list; the rest is identical. Per reference: `go-second-builtin-refs.csv`.

## What is still reported without a reference, read

Six Go taint findings, in two applications. Three are `path.Clean` or `filepath.Clean` of a request path used as a file path (`lastsaas` `main.go`, `saas-starter-kit` `response.go` twice): the cleaned path of a rooted URL cannot leave its directory, which the engine does not know. One is a JSON response written with `w.Write` that holds a request value (a JSON body is not an HTML page). Two are redirects, one of a `redirect` query parameter (probably real) and one of a URL built by a callback from the request URI. None of the six is confirmed or dismissed here beyond this reading.

## False positives on code that is not a test of anything: clean projects

chi (55 Go files) gave 4 findings with the first version of the specification and echo (47 Go files) none. With the current one chi gives 3, all `http.Redirect`: two in its profiler (the request URI plus a constant suffix, which net/http turns into a rooted path, so they are not exploitable) and one in `strip.go` where the query string of the request is appended after a `?` to a cleaned path. The engine does not know that `http.Redirect` cleans a path-only target or that text after a `?` cannot change the host. Known and left; echo has none.

## Limits

- The measurement has the limits of RESULTS.md (a sink within 2 lines, one run, a reference set from a commercial engine) and these: the front end reads one directory as one package and ignores build tags and test files; a type's methods are found only when they are in the file that declares the type; generics, `go:generate` and cgo are not followed; struct values lose their class when built by a composite literal that is then stored in a field.
- Sources of other frameworks are not in the specification (beego, goa, buffalo, fasthttp) and a handler registered by one of them is analyzed only through the standard library types its parameters declare.

## Update, 21 November 2026: the three chi redirects

The two `http.Redirect(w, r, r.RequestURI+"/", ...)` findings in chi's profiler and the `fmt.Sprintf("%s?%s", path, r.URL.RawQuery)` redirect in `strip.go` are no longer reported. `net/http` cleans a path-only redirect target, so the request URI is treated like the request path, and a `fmt.Sprintf` with a constant format is safe as a redirect target when every unsafe value comes after a `?` or `#` of the format or after a constant that starts a path of this site. A value placed first (`"%s?a=1"`) or as the host (`"https://%s/"`) still reports. chi now gives no taint finding and echo none. The VulnBench Go redirect references (ardanservice, gobase, goxygen, saas-starter-kit) are located exactly as before. The published runs above are unchanged.
