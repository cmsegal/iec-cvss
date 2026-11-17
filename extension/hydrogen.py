from .model import *

def mk(vals): return dict(zip(FRS, vals))
T = {'B': mk([3,3,3,3,3,3,2]), 'TB': mk([2,2,3,2,2,2,3]), 'PB': mk([2,2,3,1,3,2,4]), 'PU': mk([2,2,3,1,3,2,3])}
V1 = dict(id='V1', zone='B', base='AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H', frs=['RDF','RA'], zones=['B','PB','PU'], path=['B'])
V2 = dict(id='V2', zone='TB', base='AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L', frs=['IAC','UC','SI'], zones=['TB'], path=['B','TB'])
V3 = dict(id='V3', zone='PU', base='AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', frs=['SI','RA'], zones=['PU'], path=['B','PB','PU'])
ALL = [V1, V2, V3]
tri = lambda s, z: (s[z]['RDF'], s[z]['RA'], s[z]['SI'])
def show(s): return '; '.join(f"{z}{tri(s,z)}" for z in T)

def report(name, vulns, theta=(4,8)):
    m = Model(T, T, vulns, theta)
    s, vecs, tr = m.run()
    print(f"== {name}")
    for k, (vv, ss) in enumerate(tr):
        if vv: print(f"  round {k}: " + ', '.join(f"{i}:{x[0]}/{x[1]}={x[2]}" for i, x in vv.items()) + "  ->  " + show(ss))
        else: print(f"  round 0 baseline -> {show(ss)}")
    l, _, _ = m.lfp(); print("  delta=", sum(s[z][f]-l[z][f] for z in T for f in FRS))
    g3 = gaps(T, s, ['RDF','RA','SI']); gall = gaps(T, s)
    print("  gaps(RDF,RA,SI)=", len(g3), " gaps(all FRs)=", len(gall), sorted(gall.items()))
    return m, s, vecs, tr

if __name__ == '__main__':
    for v in ALL: print(v['id'], 'base', base_score(v['base']), 'req', Model(T,T,ALL).req(v))
    m, s0, _, _ = report('Original C={V1,V2,V3}', ALL)
    report('Scenario A: C\\{V1}', [V2, V3])
    report('Scenario B: C\\{V3}', [V1, V2])
    # Baselines
    print("== Baselines (original C)")
    base = {v['id']: base_score(v['base']) for v in ALL}
    sb = m.F_scores(base); print("  base-CVSS only:", base, show(sb), "gaps3", len(gaps(T, sb, ['RDF','RA','SI'])), "gapsAll", len(gaps(T,sb)))
    one = m.G(T); s1 = m.F(one); print("  one-way (G at s_bar, then F):", {k:x[2] for k,x in one.items()}, show(s1), "gaps3", len(gaps(T, s1, ['RDF','RA','SI'])), "gapsAll", len(gaps(T,s1)))
    for name, vs in [('A', [V2,V3]), ('B', [V1,V2])]:
        mm = Model(T, T, vs)
        sb = mm.F_scores({v['id']: base_score(v['base']) for v in vs})
        o = mm.F(mm.G(T)); fp,_,_ = mm.run()
        print(f"  Scenario {name}: base-only {show(sb)} g3={len(gaps(T,sb,['RDF','RA','SI']))} | one-way {show(o)} g3={len(gaps(T,o,['RDF','RA','SI']))} | coupled {show(fp)} g3={len(gaps(T,fp,['RDF','RA','SI']))}")
    # threshold enumeration
    import itertools
    reach = set()
    levels = {z: {f: range(0, T[z][f]+1) for f in ['RDF','IAC','UC']} for z in T}
    for v in ALL:
        for rdfs in itertools.product(*[levels[z]['RDF'] for z in v['path']]):
            for iac in levels[v['zone']]['IAC']:
                for uc in levels[v['zone']]['UC']:
                    mav = lvl2(min(rdfs), 'AV'); mpr = lvl2(min(iac, uc), 'PR')
                    reach.add(env(v['base'], m.req(v), mav, mpr))
    E = sorted(reach); print("reachable", len(E), E)
    pts = [E[0]-1] + E  # representatives: below e1 and each e_j (interval (e_{j-1}, e_j] contains e_j)
    reps = [0.0] + [e for e in E] + [10.01]
    # cells: I0=[0,e1], Ij=(ej,ej+1], Im=(em,10]; representative of I0 = e1 (theta<=e1), Ij -> e_{j+1}, Im -> 10.0 + eps
    cellrep = [E[0]] + [E[j+1] for j in range(len(E)-1)] + [10.05]
    outcomes = {}
    for i in range(len(cellrep)):
        for j in range(i, len(cellrep)):
            mm = Model(T, T, ALL, (cellrep[i], cellrep[j]))
            fp, _, _ = mm.run()
            key = show(fp); outcomes.setdefault(key, []).append((i, j))
    print("cells", sum(len(v) for v in outcomes.values()), "distinct", len(outcomes))
    for k, v in sorted(outcomes.items(), key=lambda kv: -len(kv[1])): print(len(v), k)
