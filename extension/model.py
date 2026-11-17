"""Independent re-implementation of the paper's F/G maps with explicit upstream paths."""
import math, itertools

def ru(x):
    i = round(x * 100000)
    return i / 100000 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10

AV = {'N': .85, 'A': .62, 'L': .55, 'P': .2}; AC = {'L': .77, 'H': .44}; UI = {'N': .85, 'R': .62}
CIA = {'H': .56, 'L': .22, 'N': 0}; REQ = {'H': 1.5, 'M': 1.0, 'L': .5}
def PRw(p, ch): return {'N': .85, 'L': .68 if ch else .62, 'H': .5 if ch else .27}[p]
def parse(v): return dict(x.split(':') for x in v.split('/') if not x.startswith('CVSS'))

def env(base, req, mav=None, mpr=None):
    b = parse(base); ch = b['S'] == 'C'
    av = mav or b['AV']; pr = mpr or b['PR']
    cr, ir, ar = [REQ[x] for x in req]
    miss = min(1 - (1 - cr * CIA[b['C']]) * (1 - ir * CIA[b['I']]) * (1 - ar * CIA[b['A']]), 0.915)
    mi = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13 if ch else 6.42 * miss
    me = 8.22 * AV[av] * AC[b['AC']] * PRw(pr, ch) * UI[b['UI']]
    if mi <= 0: return 0.0
    return ru(min(1.08 * (mi + me), 10)) if ch else ru(min(mi + me, 10))

def base_score(base):
    b = parse(base); ch = b['S'] == 'C'
    iss = 1 - (1 - CIA[b['C']]) * (1 - CIA[b['I']]) * (1 - CIA[b['A']])
    imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if ch else 6.42 * iss
    ex = 8.22 * AV[b['AV']] * AC[b['AC']] * PRw(b['PR'], ch) * UI[b['UI']]
    if imp <= 0: return 0.0
    return ru(min(1.08 * (imp + ex), 10)) if ch else ru(min(imp + ex, 10))

def lvl2(level, kind):
    if kind == 'AV': return 'N' if level <= 1 else ('A' if level == 2 else 'L')
    if kind == 'PR': return 'N' if level <= 1 else ('L' if level == 2 else 'H')
    if kind == 'REQ': return 'L' if level <= 1 else ('M' if level == 2 else 'H')

FRS = ['IAC', 'UC', 'SI', 'DC', 'RDF', 'TRE', 'RA']

class Model:
    def __init__(self, target, cap, vulns, theta=(4, 8), pens=(0, 1, 2)):
        self.T, self.cap, self.V, self.theta, self.pens = target, cap, vulns, theta, pens
    def req(self, v):
        t = self.T[v['zone']]
        return ''.join(lvl2(t[f], 'REQ') for f in ('DC', 'SI', 'RA'))
    def G(self, s):
        out = {}
        for v in self.V:
            path = v['path']
            mav = 'N' if not path else lvl2(min(s[z]['RDF'] for z in path), 'AV')
            mpr = lvl2(min(s[v['zone']]['IAC'], s[v['zone']]['UC']), 'PR')
            out[v['id']] = (mav, mpr, env(v['base'], self.req(v), mav, mpr))
        return out
    def P(self, e):
        t1, t2 = self.theta
        return self.pens[0] if e < t1 else (self.pens[1] if e < t2 else self.pens[2])
    def F_scores(self, scores):
        s = {z: dict(l) for z, l in self.cap.items()}
        zp = {}
        for v in self.V:
            p = self.P(scores[v['id']])
            for z in v['zones']:
                for f in v['frs']:
                    zp[(z, f)] = max(zp.get((z, f), 0), p)
        for (z, f), p in zp.items():
            s[z][f] = max(0, self.cap[z][f] - p)
        return s
    def F(self, vecs): return self.F_scores({k: x[2] for k, x in vecs.items()})
    def run(self, start=None):
        s = {z: dict(l) for z, l in (start or self.cap).items()}
        trace = [(None, s)]
        while True:
            vecs = self.G(s); s2 = self.F(vecs)
            trace.append((vecs, s2))
            if s2 == s: return s2, vecs, trace
            s = s2
    def lfp(self):
        zero = {z: {f: 0 for f in l} for z, l in self.cap.items()}
        return self.run(zero)

def gaps(T, s, frs=FRS):
    return {(z, f): T[z][f] - s[z][f] for z in T for f in frs if s[z][f] < T[z][f]}
