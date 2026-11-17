from .model import *
def mk(vals): return dict(zip(FRS, vals))
# (IAC, UC, SI, DC, RDF, TRE, RA)
T = {'DMZ': mk([4,3,3,3,4,3,3]), 'TB': mk([3,2,3,3,2,3,3]), 'PB': mk([2,2,2,2,4,2,2]), 'IED': mk([1,1,3,2,1,2,3])}
CL = ['DMZ']; IP = ['DMZ', 'TB', 'PB']
c4 = dict(id='c4 CVE-2023-30897', zone='TB', base='AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', frs=['UC','SI','IAC'], zones=['TB'], path=CL)
c5 = dict(id='c5 CVE-2018-8118', zone='TB', base='AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H', frs=['SI','DC','RA'], zones=['TB'], path=CL)
c6 = dict(id='c6 CVE-2024-43599', zone='TB', base='AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', frs=['SI','DC','RA'], zones=['TB'], path=CL)
c1 = dict(id='c1 CVE-2021-33719', zone='IED', base='AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', frs=['SI','RA','UC'], zones=['IED'], path=IP)
c2 = dict(id='c2 CVE-2019-10931', zone='IED', base='AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', frs=['SI','RA'], zones=['IED'], path=IP)
c3 = dict(id='c3 CVE-2021-41769', zone='IED', base='AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', frs=['DC','IAC','RDF'], zones=['IED'], path=IP)
c0 = dict(id='c0 CVE-2022-40684', zone='DMZ', base='AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', frs=['RDF','RA'], zones=['DMZ','TB','PB','IED'], path=[])
S1 = [c4, c5, c6, c1, c2, c3]
def vec(s, z): return tuple(s[z][f] for f in FRS)
def show(s): return '; '.join(f"{z}{vec(s,z)}" for z in T)
def report(name, vulns):
    m = Model(T, T, vulns); s, vecs, tr = m.run()
    print('==', name)
    for k, (vv, ss) in enumerate(tr):
        if vv:
            print(f'  round {k}:')
            for i, x in vv.items(): print(f'     {i}: MAV {x[0]} MPR {x[1]} E={x[2]}  P={m.P(x[2])}')
            print('     ->', show(ss))
        else: print('  round 0 baseline ->', show(ss))
    l, _, _ = m.lfp(); print('  delta=', sum(s[z][f]-l[z][f] for z in T for f in FRS))
    g = gaps(T, s); print('  gaps=', len(g), 'notches=', sum(g.values()))
    for z in T: print('    ', z, ' '.join(f"{f}:{T[z][f]}/{s[z][f]}{'*'*(T[z][f]-s[z][f])}" for f in FRS))
    bs = {v['id']: base_score(v['base']) for v in vulns}
    sb = m.F_scores(bs); gb = gaps(T, sb)
    o = m.F(m.G(T)); go = gaps(T, o)
    print('  base-only', bs, 'gaps', len(gb), 'notches', sum(gb.values()))
    print('  one-way gaps', len(go), 'notches', sum(go.values()))
    return s
for v in S1 + [c0]: print(v['id'], 'base', base_score(v['base']), 'req', Model(T,T,S1).req(v))
s1 = report('Scenario 1', S1)
s2 = report('Scenario 2', S1 + [c0])
