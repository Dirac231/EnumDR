## What is this?
Enum "Done Right" is a collection of notes on service enumeration i've put together during my experience.

## How to use
- ```Enumeration.md``` is a file containing a compendium of techniques to enumerate a variety of services
- ```Scanning.sh``` is a collection of functions I wrote to automate some of the routine checks on known services.

To use it effectively, you can paste the functions in your ```~/.bashrc``` or equivalent, so that they become loaded automatically in every terminal session.  You can then use the functions like this:

```bash
[function_name] [target] [port]
```
You will also need to install ```seclists```, as some of the functions attempt to guess weak credentials for authentication services.

- ```sudo apt install seclists```
