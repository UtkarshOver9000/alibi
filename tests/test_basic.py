from ittravel.detect import detect_impossible_travel
from ittravel.synthetic_data import generate_synthetic


def test_detect_runs():
    df = generate_synthetic(2000, seed=3)
    out = detect_impossible_travel(df)
    assert "is_impossible_travel" in out.columns
