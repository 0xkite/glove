#!/usr/bin/env python3
"""Train a glove denial model from `glove-denial-replay rows` output.

Standard library only. Reads feature rows (JSON lines), fits logistic
regression or small gradient-boosted trees on the `train` split, picks the
flag and terminate thresholds on the `validate` split (or `train` when there
is none), and writes a model file that `load_denial_model` accepts.

Thresholds are chosen per session, not per row, because a session is what
gets flagged or terminated:
  * terminate: the lowest score that no more than --terminate-budget of
    benign behaviour reaches (default 0: no benign session, and no
    misbehaving session before its onset, would have been terminated);
  * flag: the lowest score that no more than --flag-budget of benign
    behaviour reaches (default 0.05).

    glove-denial-replay schema > schema.json
    glove-denial-replay rows manifest.jsonl > rows.jsonl
    tools/denial_model/train.py --schema schema.json --rows rows.jsonl \\
        --type gbdt --out model.json
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict

MAX_ROWS_PER_SESSION = 64


def load_rows(path, feature_count):
    by_session = defaultdict(list)
    with open(path, encoding="ascii") as stream:
        for number, line in enumerate(stream, 1):
            row = json.loads(line)
            features = row["features"]
            if len(features) != feature_count or row["label"] not in (0, 1):
                sys.exit(f"{path}:{number}: row does not match the schema")
            if not all(isinstance(x, (int, float)) and math.isfinite(x) for x in features):
                sys.exit(f"{path}:{number}: non-finite feature")
            by_session[(row["split"], row["session"])].append(
                (row["t_ms"], float(row["label"]), [float(x) for x in features])
            )
    return by_session


def thin(rows):
    """At most MAX_ROWS_PER_SESSION evenly spaced rows, always the last one
    and the first row of each label, so long sessions do not dominate."""
    if len(rows) <= MAX_ROWS_PER_SESSION:
        return rows
    step = len(rows) / MAX_ROWS_PER_SESSION
    keep = {int(i * step) for i in range(MAX_ROWS_PER_SESSION)}
    keep.add(len(rows) - 1)
    for label in (0.0, 1.0):
        first = next((i for i, row in enumerate(rows) if row[1] == label), None)
        if first is not None:
            keep.add(first)
    return [rows[i] for i in sorted(keep)]


def sigmoid(value):
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exp = math.exp(value)
    return exp / (1.0 + exp)


def class_weights(labels):
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        sys.exit("training split needs both benign and misbehaving rows")
    return len(labels) / (2.0 * negatives), len(labels) / (2.0 * positives)


def train_logistic(xs, ys, epochs, rate, l2):
    count = len(xs[0])
    weights = [0.0] * count
    bias = 0.0
    velocity = [0.0] * (count + 1)
    w_neg, w_pos = class_weights(ys)
    total = len(xs)
    for _ in range(epochs):
        grad = [0.0] * count
        grad_bias = 0.0
        for x, y in zip(xs, ys):
            margin = bias + sum(w * v for w, v in zip(weights, x))
            error = (sigmoid(margin) - y) * (w_pos if y else w_neg)
            grad_bias += error
            for i, v in enumerate(x):
                if v:
                    grad[i] += error * v
        for i in range(count):
            step = grad[i] / total + l2 * weights[i]
            velocity[i] = 0.9 * velocity[i] - rate * step
            weights[i] += velocity[i]
        velocity[count] = 0.9 * velocity[count] - rate * grad_bias / total
        bias += velocity[count]
    return bias, weights


def bin_edges(xs, feature, bins):
    values = sorted({x[feature] for x in xs})
    if len(values) <= 1:
        return []
    if len(values) <= bins:
        return [(a + b) / 2.0 for a, b in zip(values, values[1:])]
    return sorted({values[int(len(values) * k / bins)] for k in range(1, bins)})


def best_split(indices, xs, grads, hessians, edges, l2, min_hessian):
    g_total = sum(grads[i] for i in indices)
    h_total = sum(hessians[i] for i in indices)
    base = g_total * g_total / (h_total + l2)
    best = None
    for feature, thresholds in enumerate(edges):
        if not thresholds:
            continue
        g_bins = [0.0] * (len(thresholds) + 1)
        h_bins = [0.0] * (len(thresholds) + 1)
        for i in indices:
            value = xs[i][feature]
            slot = 0
            while slot < len(thresholds) and value > thresholds[slot]:
                slot += 1
            g_bins[slot] += grads[i]
            h_bins[slot] += hessians[i]
        g_left = h_left = 0.0
        for slot, threshold in enumerate(thresholds):
            g_left += g_bins[slot]
            h_left += h_bins[slot]
            h_right = h_total - h_left
            if h_left < min_hessian or h_right < min_hessian:
                continue
            g_right = g_total - g_left
            gain = g_left * g_left / (h_left + l2) + g_right * g_right / (h_right + l2) - base
            if gain > 1e-9 and (best is None or gain > best[0]):
                best = (gain, feature, threshold)
    return best


def build_tree(indices, xs, grads, hessians, edges, depth, rate, l2, min_hessian):
    """Nodes in breadth-first order, so every child follows its parent."""
    nodes = []
    queue = [(indices, 0, None)]
    while queue:
        members, level, slot = queue.pop(0)
        index = len(nodes)
        if slot is not None:
            parent, side = slot
            nodes[parent][side] = index
        split = None
        if level < depth and len(members) > 1:
            split = best_split(members, xs, grads, hessians, edges, l2, min_hessian)
        if split is None:
            g = sum(grads[i] for i in members)
            h = sum(hessians[i] for i in members)
            nodes.append({"feature": -1, "threshold": 0.0, "left": 0, "right": 0,
                          "value": -rate * g / (h + l2)})
            continue
        _, feature, threshold = split
        nodes.append({"feature": feature, "threshold": threshold, "left": 0, "right": 0,
                      "value": 0.0})
        left = [i for i in members if xs[i][feature] <= threshold]
        right = [i for i in members if xs[i][feature] > threshold]
        queue.append((left, level + 1, (index, "left")))
        queue.append((right, level + 1, (index, "right")))
    return nodes


def tree_value(nodes, x):
    at = 0
    while nodes[at]["feature"] >= 0:
        node = nodes[at]
        at = node["left"] if x[node["feature"]] <= node["threshold"] else node["right"]
    return nodes[at]["value"]


def train_gbdt(xs, ys, rounds, depth, rate, l2, bins):
    w_neg, w_pos = class_weights(ys)
    prior = sum(ys) / len(ys)
    bias = math.log(prior / (1.0 - prior))
    margins = [bias] * len(xs)
    edges = [bin_edges(xs, f, bins) for f in range(len(xs[0]))]
    trees = []
    for _ in range(rounds):
        grads, hessians = [], []
        for margin, y in zip(margins, ys):
            p = sigmoid(margin)
            weight = w_pos if y else w_neg
            grads.append(weight * (p - y))
            hessians.append(weight * max(p * (1.0 - p), 1e-6))
        nodes = build_tree(list(range(len(xs))), xs, grads, hessians, edges, depth, rate, l2, 1.0)
        trees.append({"nodes": nodes})
        for i, x in enumerate(xs):
            margins[i] += tree_value(nodes, x)
    return bias, trees


def scorer(model):
    if model["type"] == "logistic":
        return lambda x: sigmoid(model["bias"] + sum(w * v for w, v in zip(model["weights"], x)))
    return lambda x: sigmoid(model["bias"] + sum(tree_value(t["nodes"], x) for t in model["trees"]))


def benign_maxima(sessions, score):
    """Per session, the highest score on its benign rows (before any onset)."""
    maxima = []
    for rows in sessions.values():
        benign = [score(x) for _, label, x in rows if label == 0.0]
        if benign:
            maxima.append(max(benign))
    return sorted(maxima)


def threshold_at(maxima, budget):
    """Lowest threshold that at most BUDGET of sessions' benign rows reach."""
    if not maxima:
        return 0.5
    allowed = int(math.floor(budget * len(maxima)))
    ceiling = maxima[len(maxima) - 1 - allowed] if allowed < len(maxima) else 0.0
    return min(math.nextafter(ceiling, math.inf) + 1e-6, 1.0)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--schema", required=True)
    parser.add_argument("--rows", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--type", choices=("logistic", "gbdt"), default="gbdt")
    parser.add_argument("--terminate-budget", type=float, default=0.0)
    parser.add_argument("--flag-budget", type=float, default=0.05)
    parser.add_argument("--epochs", type=int, default=150)
    parser.add_argument("--rounds", type=int, default=40)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--rate", type=float, default=0.2)
    parser.add_argument("--l2", type=float, default=1.0)
    parser.add_argument("--bins", type=int, default=16)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    random.seed(args.seed)

    with open(args.schema, encoding="ascii") as stream:
        schema = json.load(stream)
    names = schema["features"]
    sessions = load_rows(args.rows, len(names))
    train = {k: thin(v) for k, v in sessions.items() if k[0] == "train"}
    validate = {k: v for k, v in sessions.items() if k[0] == "validate"} or train
    if not train:
        sys.exit("no rows in the train split")
    xs = [x for rows in train.values() for _, _, x in rows]
    ys = [y for rows in train.values() for _, y, _ in rows]

    model = {
        "format": "glove-denial-model",
        "version": 1,
        "feature_schema": schema["feature_schema"],
        "features": names,
        "type": args.type,
        "bias": 0.0,
        "weights": [],
        "trees": [],
        "flag_threshold": 0.5,
        "terminate_threshold": 0.9,
    }
    if args.type == "logistic":
        model["bias"], model["weights"] = train_logistic(xs, ys, args.epochs, args.rate, args.l2)
    else:
        model["bias"], model["trees"] = train_gbdt(
            xs, ys, args.rounds, args.depth, args.rate, args.l2, args.bins
        )

    maxima = benign_maxima(validate, scorer(model))
    terminate = threshold_at(maxima, args.terminate_budget)
    flag = min(threshold_at(maxima, args.flag_budget), terminate)
    model["flag_threshold"] = max(flag, 1e-6)
    model["terminate_threshold"] = terminate
    with open(args.out, "w", encoding="ascii") as stream:
        json.dump(model, stream, separators=(",", ":"))
    print(
        f"trained {args.type} on {len(xs)} rows from {len(train)} sessions; "
        f"thresholds flag={model['flag_threshold']:.4f} "
        f"terminate={model['terminate_threshold']:.4f} "
        f"from {len(maxima)} validation sessions",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
