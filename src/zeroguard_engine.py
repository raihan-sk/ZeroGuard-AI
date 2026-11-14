
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp


def prepare_features(frame, bundle):
    features = bundle['features']
    missing = [c for c in features if c not in frame.columns]
    if missing:
        raise ValueError('Input is missing required feature columns: ' + ', '.join(missing))
    x = frame.loc[:, features].copy()
    categories = bundle['categories']
    for col, allowed in categories.items():
        vals = x[col].astype('string').fillna('Missing')
        vals = vals.where(vals.isin(allowed), 'Missing')
        x[col] = pd.Categorical(vals, categories=allowed)
    for col in features:
        if col not in categories:
            x[col] = (pd.to_numeric(x[col], errors='coerce')
                      .replace([np.inf, -np.inf], np.nan)
                      .astype('float32'))
    return x


def score_flows(frame, bundle, batch_size=3000):
    if len(frame) == 0:
        return np.array([], dtype=float)
    out = []
    for start in range(0, len(frame), batch_size):
        batch = frame.iloc[start:start + batch_size]
        processed = prepare_features(batch, bundle)
        out.append(bundle['model'].predict_proba(processed)[:, 1])
    return np.concatenate(out)


def percent(mask):
    return 100.0 * float(np.mean(mask)) if len(mask) else float('nan')


def recommend_threshold(verified_benign, bundle):
   
    base = float(bundle['frozen_threshold'])
    n_min = int(bundle.get('min_verified_benign', 300))
    if len(verified_benign) < n_min:
        return {'accepted': False, 'reason': f'Need at least {n_min} independently verified benign flows',
                'threshold': base, 'ks': None, 'trusted_gain_pp': 0., 'guard_known_loss_pp': 0.}
    current_scores = score_flows(verified_benign, bundle)
    old_scores = np.asarray(bundle['reference_benign_scores'], dtype=float)
    guard_scores = np.asarray(bundle['guard_known_scores'], dtype=float)
    cutoffs = bundle['adaptation_policy']
    ks = float(ks_2samp(old_scores, current_scores).statistic)
    if ks < cutoffs['ks_cutoff']:
        return {'accepted': False, 'reason': 'Drift gate closed; historical threshold retained',
                'threshold': base, 'ks': ks, 'trusted_gain_pp': 0., 'guard_known_loss_pp': 0.}
    candidate = float(np.clip(np.quantile(current_scores, 1 - cutoffs['fpr_budget']),
                              base, min(1., base + cutoffs['maximum_threshold_increase'])))
    original_known = percent(guard_scores > base)
    original_benign_fpr = percent(current_scores > base)
    eligible = []
    for t in np.linspace(base, candidate, 101):
        loss = original_known - percent(guard_scores > t)
        gain = original_benign_fpr - percent(current_scores > t)
        if loss <= cutoffs['maximum_known_recall_loss_pp'] + 1e-9 and gain >= cutoffs['minimum_benign_fpr_gain_pp']:
            eligible.append((float(t), float(gain), float(loss)))
    if eligible:
        chosen, gain, loss = max(eligible, key=lambda z:z[0])
        return {'accepted': True, 'reason': 'Candidate passed trusted known-attack guard',
                'threshold': chosen, 'ks': ks, 'trusted_gain_pp': gain,
                'guard_known_loss_pp': loss}
    return {'accepted': False, 'reason': 'Adaptation rejected: insufficient safe false-alarm improvement',
            'threshold': base, 'ks': ks, 'trusted_gain_pp': 0., 'guard_known_loss_pp': 0.}
