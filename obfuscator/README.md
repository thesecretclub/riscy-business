# obfuscator

Set up the virtual environment and install the dependencies:

```sh
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Build the obfuscator:

```sh
cmake -B build -G Ninja
cmake --build build
```

Run the tests without obfuscation:

```sh
python test.py --no-obfuscator riscvm.exe
```

Run the obfuscation tests:

```sh
python test.py riscvm.exe
```
