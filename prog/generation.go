// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"sync"
)
// 在生成种子时，有意插入能触发arch/riscv下的系统调用
var (
    riscvMu       sync.RWMutex
    riscvSyscalls []*Syscall
)

func AddRiscvSyscall(syscall *Syscall) {
    if syscall == nil || syscall.Attrs.Disabled || syscall.Attrs.NoGenerate {
        return
    }
    for _, s := range riscvSyscalls {
        if s == syscall {
            return
        }
    }
    riscvMu.Lock()
    defer riscvMu.Unlock()
    riscvSyscalls = append(riscvSyscalls, syscall)
}

func GetRiscvSyscalls() []*Syscall {
    riscvMu.RLock()
    defer riscvMu.RUnlock()
    out := make([]*Syscall, len(riscvSyscalls))
    copy(out, riscvSyscalls)
    return out
}

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	riscvSyscalls := GetRiscvSyscalls()
	for len(p.Calls) < ncalls {
        if len(riscvSyscalls) > 0 && r.Intn(10) < 3 {
            cnt := 1 + r.Intn(3)
            for k := 0; k < cnt && len(p.Calls) < ncalls; k++ {
                syscall := riscvSyscalls[r.Intn(len(riscvSyscalls))]
                calls := r.generateParticularCall(s, syscall)
                for _, c := range calls {
                    s.analyze(c)
                    p.Calls = append(p.Calls, c)
                }
            }
            continue
        }

		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}
