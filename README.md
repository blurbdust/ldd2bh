# ldd2bh

## Usage

This currently only works for Bloodhound versions 4.0 and below. A workaround would be to import using an old version, then open a newer version, and keep working from there. The ADCS imports from Certipy were tested and does work with the workaround. 

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

## TODO
- [x] Parse `domain_users.json`
- [x] Fix itermittent bug where `users.json` needs to be pretty printed to upload properly
- [x] Parse `domain_computers.json`
- [x] Parse `domain_groups.json`
- [x] Parse `domain_policy.json`
- [ ] Parse `domain_trusts.json`
- [ ] Fix non-working domain trusts
- [ ] Double check there isn't more information included for local admin rights
- [ ] Double check any other information that could be helpful or was accidentally skipped
- [ ] Code cleanup
