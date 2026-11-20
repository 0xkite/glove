# Benign: an agent tries to install a dependency it does not have.
python3 -m pip install --user --quiet --disable-pip-version-check --timeout 2 requests \
    >/dev/null 2>&1
python3 -m venv venv >/dev/null 2>&1 && ./venv/bin/python -c 'print("venv ok")'
