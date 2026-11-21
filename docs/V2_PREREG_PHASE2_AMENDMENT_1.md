# LG-IDS V2 -- Phase 2 pre-registration, Amendment 1 (orientation normaliser + class-weight selection)

Status: written and pinned (`PREREG_PHASE2_AMENDMENT_1_SHA256` in `common/schemas.py`, checked by
`verify_v2_lock()`) **before** any model is trained on the amended data. It amends `docs/V2_PREREG_PHASE2.md`
(itself unchanged, still pinned); where the two differ, this document wins for every run made with
`config/v2_phase2_v2_1.json`. Implementation choices it does not fix are logged in `docs/V2_DECISIONS.md` (D39+).

## 0. Disclosure: this amendment is made AFTER seeing v2_0 val results

It is not a pre-registration in the strict sense. Phase 2 was run once as pre-registered on `v2_0_v1equiv`
(results/22-26). Its val results showed:

- SPEC_G1 (primary, sqrt weights) labelled 43 % of G1 val port_scan flows syn_flood, identically in all 5 seeds
  (`docs/V2_DECISIONS.md` T3).
- The cause (results/diag_01, diag_01b, diag_02): CICFlowMeter wrote 56 % of G1 val port_scan flows backwards --
  the victim's window-0 RST/ACK as the first ("forward") packet, the scanner's SYN as backward -- versus 5 % in
  train. 99.6 % of the specialist's port_scan -> syn_flood errors are such flows. Flipping them in memory
  (models NOT retrained) raised SPEC_G1's G1 port_scan recall from 0.566 to 0.998.
- **Also seen, and disclosed because it bears on section 2**: on v2_0 val the A1 ablation models trained with
  class weights "none" (and "balanced") did NOT show the port_scan failure (seed 0, own val set: SPEC_G1__none and
  SPEC_G1__balanced port_scan recall 0.999 vs 0.815 for SPEC_G1__sqrt; results/23). The weighting rule below is therefore chosen knowing that, on v2_0, "none"
  looked better than the pre-registered "sqrt". The rule is applied to v2_1 results that nobody has seen; whether
  that removes the bias is for the reader to judge. The v2_0 results stay published as they are.

## 1. Data

- All Phase 2 models are trained and evaluated on dataset **`v2_1_oriented`** = `v2_0_v1equiv` train + val with
  the orientation normaliser applied (`21b_normalise_orientation.py`, run `20261121T075025Z`; dataset manifest
  sha256 `49065567fa88a820ea8cd6b15f20cfc7bdb3a863bcd9b9c7ac8d5dc3d6afb872`).
- Normaliser: `common/orientation.py`, rule **R3**, map `config/orientation_map.json` (sha256
  `09d62055760943be26ff55335b4f5fccc5ac598ed5e981d7df7bffc92bd2a022`, pinned as `ORIENTATION_MAP_SHA256`):
  a flow is REVERSED iff `Protocol == 6 AND FWD Init Win Bytes == 0 AND Bwd Init Win Bytes > 0 AND
  SYN Flag Count >= 1 AND Total Fwd Packet == 1`; a reversed flow has every forward/backward feature pair, its
  IPs, ports and MACs swapped, Flow ID rebuilt, Down/Up Ratio recomputed, and the asymmetric / unpaired fields set
  by the map's stated defaults. Non-TCP flows are never changed. The feature set and order are unchanged; the
  boolean column `orientation_flipped` is metadata, never a model feature.
- Gate passed before building (results/orient_gate/rerun_pct_fix): R3 flags all 4,348 G1 val port_scan flows with
  FWD Init Win Bytes = 0 and exactly the port_scan rows R1 flags in train / val; benign flagged <= 0.0067 % in every
  split x group; syn_flood 1 (train) / 3 (val) rows; 0 non-TCP rows.
- **Test**: `v2_1_oriented` has no test split. The test split is normalised **once**, with the same pinned code
  and map, at the single final test run. Phase 2 never reads it (unchanged rule).

## 2. Class weights: A1 is no longer report-only

The three A1 configurations `none`, `sqrt`, `balanced` (definitions unchanged) are each trained for all
specialists and GLOBAL, all 5 seeds. **The primary configuration is chosen by this rule, applied jointly to all
specialists + GLOBAL** (one weighting for the whole system):

1. For each configuration c, compute on the full val split the **ROUTED** system (specialists of c, fallback
   group -> GLOBAL of c) **non-rare macro-F1, mean over the 5 seeds**, and its **false alarms, mean over the
   5 seeds** (benign val flows predicted as any attack; the benign-hours denominator is the same for every c).
2. Keep the configurations whose non-rare macro-F1 mean is within **0.005** of the best one.
3. Among those, pick the one with the **fewest mean false alarms**.
4. If still tied (equal means), pick `none`; if `none` is not among the tied ones, pick the first of the tied ones
   in the order `none`, `sqrt`, `balanced`.

The chosen configuration c* is "primary" from then on: ROUTED = ROUTED(c*); the flat baseline FLAT_GLOBAL =
GLOBAL of c* on every flow; calibration (24) and SHAP (25) report c*'s models; the registry (26) registers c*'s
seed-0 models as **candidate**. Step 23 writes the table that decided it. The other configurations stay reported
as ablations. A2 and A3 keep their pre-registered definitions with sqrt weights (they are not re-weighted).

## 3. Everything else is unchanged

Pooling, GEN -> GLOBAL, the shared attack pool, hyperparameters, early stopping on the 10 % inner split, seeds
0-4, the rare-class rule (`min_val_flows`), every metric and CI in section 4, calibration, SHAP, figures, the
registry (candidate only; approval / promotion manual), and the val-only rule are exactly as in
`docs/V2_PREREG_PHASE2.md`.
