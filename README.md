# CF*CK

CF*CK is a checker for files. It applies a customizable set of rules to extract information and report issues.

## What can it do?

For the analysis:

* analyze XML
* analyze SARIF

For the reporting:

* VIM Quickfix
* SARIF
* plain (in case you want to output something other than findings)

## How does it work?

The analysis module needs a set of Prolog rules. The program then queries the predicate `q(...)`, and the reporting module interprets the arguments and writes the report. The reporting and analysis have to be aware of what the results mean.

### Reporting findings

To report findings in SARIF or Quickfix format, the predicate `q` looks like:

```
q([RuleId,Level,Message,Locations,Args]) :- ...
```

`Locations` is a list of locations. Each location has the form `[Path,[StartLine,StartColumn],[Endline,EndColumn]]`.



## What about the name?

CF*CK is an abbreviation for "Config File ChecKer". It is general enough to work on any file, hence the `*`.
You could also read it as 'see if your files contain known issues'.


