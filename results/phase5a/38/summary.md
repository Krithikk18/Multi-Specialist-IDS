# Step 38 -- zero-day evaluation + verdict -- FAIL

- step 36 run `20261122T174129Z`, step 37 run `20261122T174358Z`; the full write-up is `phase_summary.md` (and results/phase5a/summary.md for the full run)

- **verdict CONFLICT** (prereg DOES_NOT_WIN, literal PER_GROUP_WINS); d +0.0000 [+0.0000, +0.0000] (n=10); FA/h d -6.145 [-9.218, -3.687] (n=5)
- Kill rule §5: not evaluated (the §3 verdict is CONFLICT; a human decision is needed).

## Checks

- PASS  val rows / order == step 36's (uid sha256)  157,558 rows
- PASS  step 37 trained on the same train file  
- PASS  step 36 and step 37 seeds match  [0, 1, 2, 3, 4]
- FAIL  verdict declared (the two readings of Amendment 2 §3 agree)  CONFLICT
