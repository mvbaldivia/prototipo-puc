import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ai-resilience"))
sys.path.insert(0, str(ROOT / "simulator"))
