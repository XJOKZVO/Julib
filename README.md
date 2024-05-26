# Julib
designed to scan for API keys within specified patterns across various types of content, including JavaScript files and web pages. It uses regular expressions to identify potential API keys based on common formats. The script also includes command-line options for specifying input and output files, verbosity level, and handling interrupts gracefully.

# Installation
```
▶ https://github.com/XJOKZVO/Julib.git
```
# Options:
```
      _           _   _   _     
     | |  _   _  | | (_) | |__  
  _  | | | | | | | | | | | '_ \ 
 | |_| | | |_| | | | | | | |_) |
  \___/   \__,_| |_| |_| |_.__/ 
                               

Usage: ruby Julib.rb [options]
    -f, --file FILE                  File containing URLs to scan
    -v, --verbose                    Print verbose output
    -o, --output FILE                Output file to store results
```
# Usage:
```
ruby Julib.rb -f urls_js.txt -v -o outputs_js.txt
```
