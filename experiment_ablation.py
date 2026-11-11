#!/usr/bin/env python3
"""Ablatie de hash pentru atacul DoS targetat: acelasi scop (2s+1 iteme pe o
pereche-tinta fixa), doua hash-uri, doua regimuri de cost.

  - brat blake2 (one-way): atacatorul NU poate inversa -> macina candidati pana
    pica (2s+1) pe pereche. Cost = numarul de candidati generati (fiecare = o
    evaluare forward). Prezis (2s+1)*nB^2/2. Scalare Theta(nB^2) -> panta 2.

  - brat murmur (inversabil): atacatorul construieste direct, prin inversare,
    (2s+1) iteme pe pereche. Cost = numarul de inversari = 2s+1, INDEPENDENT de
    nB. O(1) -> panta 0.

Metrica e numarata in "operatii la nivel de hash": pentru blake, evaluari forward;
pentru murmur, inversari. O inversare = ~6 inmultiri + cateva xor-uri, adica
aproximativ costul unei evaluari forward -- deci comparatia e corecta, nu ascunde
munca in inversare.

Metrici per celula: medie pe >=30 repetari (bratul blake e stocastic; cel murmur
e determinist), interval de incredere 95%, raport masurat/prezis, panta log-log.
"""
import csv
import math
from hashes import blake2_64
from experiment_dos import grind_dos, predicted_cost
from murmur_invert import craft_items_on_pair


def loglog_slope(xs, ys) -> float:
    """Panta regresiei liniare a lui log(y) in functie de log(x)."""
    lx = [math.log(x) for x in xs]
    ly = [math.log(y) for y in ys]
    n = len(xs)
    mx, my = sum(lx) / n, sum(ly) / n
    num = sum((a - mx) * (b - my) for a, b in zip(lx, ly))
    den = sum((a - mx) ** 2 for a in lx)
    return num / den


def blake_arm(nB_values, s, reps):
    """Grinding stocastic; intoarce media, CI95, prezis si raport per nB."""
    rows = {}
    for nB in nB_values:
        costs = [grind_dos(nB, s, blake2_64) for _ in range(reps)]
        mean = sum(costs) / len(costs)
        var = sum((c - mean) ** 2 for c in costs) / (len(costs) - 1)
        stderr = (var / len(costs)) ** 0.5
        pred = predicted_cost(nB, s)
        rows[nB] = {"mean": mean, "ci95": 1.96 * stderr,
                    "pred": pred, "ratio": mean / pred}
    return rows


def murmur_arm(nB_values, s):
    """Constructie directa; costul = numarul de inversari = 2s+1, determinist.
    Construim efectiv itemele (dovada ca aterizeaza pe pereche e in
    murmur_invert, verificata la nivel de modul)."""
    rows = {}
    for nB in nB_values:
        items = craft_items_on_pair(nB, 2 * s + 1)
        rows[nB] = {"cost": len(items), "pred": 2 * s + 1, "ratio": 1.0}
    return rows


if __name__ == "__main__":
    nB_values = [8, 16, 32, 64]
    reps = 30
    csv_rows = []

    print("=== ABLATIE DE HASH: cost DoS targetat (operatii vs nB) ===")
    print(f"reps={reps} pe bratul blake (stocastic); bratul murmur e determinist\n")

    for s in (1, 2, 4):
        b = blake_arm(nB_values, s, reps)
        m = murmur_arm(nB_values, s)
        need = 2 * s + 1
        print(f"--- s = {s}   (overflow-ul cere 2s+1 = {need} iteme pe pereche) ---")
        print(f"{'nB':>4} | {'blake medie':>12} | {'CI95 +/-':>10} | "
              f"{'prezis (2s+1)nB^2/2':>19} | {'raport':>6} | {'murmur cost':>11}")
        for nB in nB_values:
            rb, rm = b[nB], m[nB]
            print(f"{nB:>4} | {rb['mean']:>12.1f} | {rb['ci95']:>10.1f} | "
                  f"{rb['pred']:>19.1f} | {rb['ratio']:>6.3f} | {rm['cost']:>11}")
            csv_rows.append({"s": s, "nB": nB,
                             "blake_mean": f"{rb['mean']:.2f}",
                             "blake_ci95": f"{rb['ci95']:.2f}",
                             "blake_pred": f"{rb['pred']:.2f}",
                             "blake_ratio": f"{rb['ratio']:.4f}",
                             "murmur_cost": rm['cost']})
        bslope = loglog_slope(nB_values, [b[nB]['mean'] for nB in nB_values])
        mcosts = [m[nB]['cost'] for nB in nB_values]
        mslope = loglog_slope(nB_values, mcosts)   # y constant -> panta 0
        print(f"  panta log-log vs nB:  blake = {bslope:.3f} (prezis 2)   "
              f"murmur = {mslope:.3f} (prezis 0)\n")

    with open("ablation_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["s", "nB", "blake_mean", "blake_ci95",
                                          "blake_pred", "blake_ratio", "murmur_cost"])
        w.writeheader()
        w.writerows(csv_rows)
    print("Date scrise in ablation_results.csv (pentru graficul log-log din capitol).")
