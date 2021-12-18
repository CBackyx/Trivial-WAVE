# Trivial WAVE

```bash
python3 main.py -a mke -o Alice
python3 main.py -a grant -i admin -s Alice -p read@air-condition -r 10/9/2021:21/9/2021
python3 main.py -a prove -s Alice -p read@air-condition -t CBackyx
python3 main.py -a verify -s Alice -p read@air-condition
python3 main.py -a revoke -i Alice -s Bob -p read@air-condition -r 10/9/2021:21/9/2021
python3 main.py -a prove -s Jack -p read@air-condition -t CBackyx
```
