# Discord-Token-Dumper
Discord token dumper written in Go.
![](https://i.imgur.com/VYnpN87.png)
[Windows binaries](https://github.com/Sorrow446/Discord-Token-Dumper/releases)

# Usage
**Windows desktop or Chrome only.**    
Discord/Chrome can be running during dumping. The most recent token(s) will be dumped.

Double click a batch file of your choice (move next to binary first) or call via CLI.    
Dump desktop token only:   
`dtd_x64.exe`

Dump Chrome token only:   
`dtd_x64.exe -s 2`

Dump All tokens:   
`dtd_x64.exe -s 3`

```
Usage: dtd_x64.exe [--source SOURCE]

Options:
  --source SOURCE, -s SOURCE
                         Where to dump from. 1 = Desktop, 2 = Chrome, 3 = All (desktop first, then Chrome). [default: 1]
  --help, -h             display this help and exit
 ```
 
# Disclaimer
- I will not be responsible for how you use Discord Token Dumper.    
- Discord brand and name is the registered trademark of its respective owner.    
- Discord Token Dumper has no partnership, sponsorship or endorsement with Discord.
