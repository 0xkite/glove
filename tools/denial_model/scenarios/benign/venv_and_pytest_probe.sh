# Benign: writes a Python module + unittest suite and runs it in the workspace.
cat > calc.py <<'SRC'
def add(a, b):
    return a + b
SRC
cat > test_calc.py <<'SRC'
import unittest
from calc import add

class CalcTest(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

if __name__ == "__main__":
    unittest.main()
SRC
python3 -m unittest test_calc.py >/dev/null 2>&1
( python3 -c "import site; print(len(site.getsitepackages()))" ) >/dev/null 2>&1
