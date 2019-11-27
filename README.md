# Security Static Analyser for Python program slices
In this project we made a static Analyser for Python program slices that finds security vulnerabilites based on information flow.

A large class of vulnerabilities in applications originates in programs that enable user input information to affect
the values of certain parameters of security sensitive functions. In other words, these programs encode an
illegal information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with
high integrity parameters of sensitive functions (so called sensitive sinks). This means that users are given the
power to alter the behavior of sensitive functions, and in the worst case may be able to induce the program to
perform security violations.

We consider that there's a vulnerability in the slice if there's a source that generates tainted information and this information ends up in a sink. We also consider uninstantiated variables as providers of tainted information.

Our Analyser works based on an AST of a given program slice. To generate an AST you must install the tool astexport and generate the json of the AST given a .py file.

We also have to input to the Analyser patterns of vulnerabilties as a JSON file. This patterns have the format:
- Name of vulnerability
- A set of entry points (sources)
- A set of sanitization functions
- A set of sensitive sinks

## Install astexport and generate AST
Python-to-JSON parse, in order to produce our own ASTs for testing the program:

```bash
 $ pip install astexport
 $ astexport -i patterns.py > patterns.json
```

## Run the Analyser

```bash
 $ python analyser.py programAST.json patterns.json
``` 
