from datetime import datetime
from pathlib import Path
import pandas as pd
from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["events"])

DATA_FILE = Path(__file__).resolve().parents[3] / "data" / "sample" / "events.csv"

@router.get("/events")
def get_events(limit: int = 100):
    if not DATA_FILE.exists():
        raise HTTPException(status_code=404, detail="Sample event data not found")
    df = pd.read_csv(DATA_FILE)
    records = df.head(max(1, min(limit, 1000))).to_dict(orient="records")
    return {"count": len(records), "events": records}
