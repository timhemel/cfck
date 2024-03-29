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
q([
   key1(val1, val2, ...),
   key1(val1, ...),
   ...
]) :- ...
```

The argument of `q` is a list of Prolog functors containing values. The reporters understand these functors and convert it into output.

### Supported functors

| functor | scope| explanation | notes |
| ------- | -----| ----------- | ----- |
| toolname(Name) | log | Name is a string | ignored by quickfix |
| toolversion(Version) | log | Version is a string | ignored by quickfix |
| ruleid(RuleId) | result | RuleId is a string | |
| level(Level)  | result| Level is a string representing a valid SARIF level | quickfix translates this |
| kind(Kind)  | result| Kind is a string representing a valid SARIF kind | quickfix translates this |
| message(Message,Args)  | result| Message is a message template containing placeholders, in which the values of Args are substituted | |
| locations(Locations)  | result| Locations is a list of lists: `[ [FileName,[StartLine,StartCol],[EndLine,EndCol]], ... ]` | quickfix uses the first location |
| codeflow(Locations)  | result| Locations is a list of lists: `[ [[FileName,[StartLine,StartCol],[EndLine,EndCol]],Message], ... ]` | Not supported in quickfix. Only supports one codeflow, with one threadflow. To add more flows, use this functor more than once. Supports messages with the locations. |




## What about the name?

CF*CK is an abbreviation for "Config File ChecKer". It is general enough to work on any file, hence the `*`.
You could also read it as 'see if your files contain known issues'.


