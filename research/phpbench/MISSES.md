# Why the PHP set is mostly missed (post hoc analysis)

This analysis was written after the scores were known. It is not part of the pre-registered protocol and nothing in the engine was changed because of it. The PHP set is therefore still held out.

Scope: the analysis below covers the 66 misses among the first 78 scanned advisories. After a full disk on the work drive stopped the run at about 16:20 (13 advisories were never fetched, one was left unfinished and two failed at that moment), those 16 were run again with the same binary and script. That added 13 scanned advisories and no located reference, so the final count is 12 of 91 located, with 79 misses. The 13 added misses are not categorized here, and the figures of the table below are for the first 78. 9 advisories are not scored: 6 scan timeouts (Dolibarr, moodle) and 3 that failed again on the rerun (Dolibarr twice, AVideo once).

## Mechanical split

Proxy, computed from the working tree of the fixed commit (the vulnerable file is nearly identical outside the changed lines), not from the vulnerable state:

| group | advisories |
|---|---|
| no finding in any changed PHP file, no request source (`$_GET` and friends, `$request->`, `->input(`) in the file | 27 |
| no finding in a changed file, a framework request API in the file | 17 |
| no finding in a changed file, a superglobal source in the file | 8 |
| findings in a changed file, but not within 5 lines of the change | 14 |

## What I read

I read the changed lines of the 8 advisories of the third row and of the 17 of the second row, and a sample of the first row.

- **Third row (8):** none is a missed source-to-sink flow. Two are JavaScript or changelog-only changes, one is a sanitizer regex fix, one a configuration closure (RCE through a config value), one an access-control check, one an output of fixed arrays, one a path check whose old version was already sanitized, one a framework data grid column function.
- **Second row (17):** most are not flows either: changelogs, new files, composer changes, sanitizer configuration, Blade component rendering, second-order values from the database, an exception message built from an API argument (froxlor), a port validation in a URI class. A few are plausible taint gaps: a Laravel `$request->input('locale')` that is split and echoed back, a Mautic `$this->request->get('bundle')` placed into a view, and a Silverstripe `Convert::raw2xml` used where `raw2sql` was needed (a wrong sanitizer for SQL, which the engine treats as a sanitizer for XSS only if it knows the function, and it does not).
- **First row (27):** the typical case is a stored or second-order value, a helper function whose caller holds the source, a library-internal fix (sanitizers, Markdown, templating engines), or a change that is not code (changelog, JavaScript, policy for file downloads).

## What this means

- A large part of the misses is outside what a per-file source-to-sink engine can find. Reporting them as plain misses is correct for the product question, but it would be wrong to read the low rate as only an engine quality problem.
- The small number of plausible gaps are framework request APIs (Laravel, Symfony style `Request`), helper functions without a source in the same file, and sanitizer knowledge for framework functions.
- One false positive pattern was seen: `taint.php-xss` on arithmetic over request input (librenms `print-alert-rules.php`, line 444). The result of arithmetic is a number and cannot carry script. Not fixed here.
- 10 of the 12 located references are also reported in the fixed state, so "located" on this set does not show that the engine tells the vulnerable code from the fixed code.

## Not done

- The first row was sampled, not read in full.
- The proxy uses the fixed tree. Nothing was checked by running the engine with a changed specification.
- Fixes for the gaps above need their own issue, and a measurement on this set after them would be a development number.
