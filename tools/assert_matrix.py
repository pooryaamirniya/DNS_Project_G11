"""Assert the six evaluated scenario outcomes; must fail if reports are missing."""
import json
import sys
from pathlib import Path
expected={'frame-correct':0,'frame-incomplete':10,'frame-regression':20,
          'cjsonreal-correct':0,'cjsonreal-incomplete':10,'cjsonreal-regression':20}
if len(sys.argv)<2 or not Path(sys.argv[1]).is_file():
    raise SystemExit('missing report.json')
report=json.loads(Path(sys.argv[1]).read_text())
actual={x['scenario']:x['exit_code'] for x in report['scenarios']}
print('Expected:',expected,'\nObserved:',actual)
if actual!=expected:
    raise SystemExit(1)
print('Scenario matrix PASS')
