from pathlib import Path
import os,sysconfig
PROJECT_ROOT=Path(__file__).resolve().parents[1]
DATA_DIR=Path(os.getenv("SENTINEL_DATA_DIR",PROJECT_ROOT/"data"))
DB_PATH=Path(os.getenv("SENTINEL_DB_PATH",DATA_DIR/"sentinel.db"))
_RULES_DEFAULT=PROJECT_ROOT/"rules"
if not _RULES_DEFAULT.exists():_RULES_DEFAULT=Path(sysconfig.get_path("data"))/"share"/"sentinel-x"/"rules"
RULES_DIR=Path(os.getenv("SENTINEL_RULES_DIR",_RULES_DEFAULT))
