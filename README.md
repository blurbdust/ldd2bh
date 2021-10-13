# ldd2bh

```
usage: ldd2bh.py [-h] [-i INPUT_FOLDER] [-o OUTPUT_FOLDER] [-a] [-u] [-c] [-g]
                 [-d]

Convert ldapdomaindump to Bloodhound

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_FOLDER, --input INPUT_FOLDER
                        Input Directory for ldapdomaindump data, default:
                        current directory
  -o OUTPUT_FOLDER, --output OUTPUT_FOLDER
                        Output Directory for Bloodhound data, default: current
                        directory
  -a, --all             Output all files, default: True
  -u, --users           Output only users, default: False
  -c, --computers       Output only computers, default: False
  -g, --groups          Output only groups, default: False
  -d, --domains         Output only domains, default: False

Examples:
python3 ldd2bh.py -i ldd -o bh
```
