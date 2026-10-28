// Package demesne runs demesne's runtime from Go: the claims and session builders, the policy decision point, the
// holds resolver, the read checks and the write builders that @foir/demesne and the Rust crates run.
//
// The runtime is the Rust crate, compiled once to WebAssembly and run here on wazero, with no cgo, so every answer is
// the one the Rust and TypeScript runtimes give. Its operations take the projections demesne emits for a spec, which
// `demesne emit <spec> --target go projections` writes as Go values. `demesne emit <spec> --target go framework <pkg>`
// writes a typed package over them: a Surface with a check per object and verb, the holds resolvers and the session
// setup.
package demesne

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed runtime.wasm
var module []byte

// Runtime runs demesne's runtime. It compiles the module once and keeps a pool of instances, so its methods are safe
// for concurrent use. Close it when it is no longer needed.
type Runtime struct {
	wasm     wazero.Runtime
	compiled wazero.CompiledModule
	mu       sync.Mutex
	idle     []*instance
}

type instance struct {
	mod                          api.Module
	alloc, free, call, authorize api.Function
}

// Error is the runtime refusing an operation, in its own words: a missing or mistyped argument, or a projection it
// can't read.
type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

type holdsKey struct{}

// New compiles demesne's runtime.
func New(ctx context.Context) (*Runtime, error) {
	w := wazero.NewRuntime(ctx)
	_, err := w.NewHostModuleBuilder("demesne").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, ptr, n uint32) uint32 {
			holds, _ := ctx.Value(holdsKey{}).(func(string) bool)
			perm, ok := m.Memory().Read(ptr, n)
			if !ok || holds == nil || !holds(string(perm)) {
				return 0
			}
			return 1
		}).
		Export("demesne_holds").
		Instantiate(ctx)
	if err == nil {
		var c wazero.CompiledModule
		if c, err = w.CompileModule(ctx, module); err == nil {
			return &Runtime{wasm: w, compiled: c}, nil
		}
	}
	return nil, errors.Join(fmt.Errorf("demesne: compile the runtime: %w", err), w.Close(ctx))
}

// Close releases the runtime and every instance it holds.
func (r *Runtime) Close(ctx context.Context) error {
	return r.wasm.Close(ctx)
}

func (r *Runtime) take(ctx context.Context) (*instance, error) {
	r.mu.Lock()
	if n := len(r.idle); n > 0 {
		in := r.idle[n-1]
		r.idle = r.idle[:n-1]
		r.mu.Unlock()
		return in, nil
	}
	r.mu.Unlock()
	mod, err := r.wasm.InstantiateModule(ctx, r.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, fmt.Errorf("demesne: start a runtime instance: %w", err)
	}
	return &instance{
		mod:       mod,
		alloc:     mod.ExportedFunction("demesne_alloc"),
		free:      mod.ExportedFunction("demesne_free"),
		call:      mod.ExportedFunction("demesne_call"),
		authorize: mod.ExportedFunction("demesne_authorize"),
	}, nil
}

func (r *Runtime) put(in *instance) {
	r.mu.Lock()
	r.idle = append(r.idle, in)
	r.mu.Unlock()
}

func (r *Runtime) run(ctx context.Context, export func(*instance) api.Function, a, b string) ([]byte, error) {
	in, err := r.take(ctx)
	if err != nil {
		return nil, err
	}
	out, err := in.run(ctx, export(in), a, b)
	if err != nil {
		return nil, errors.Join(err, in.mod.Close(ctx))
	}
	r.put(in)
	return out, nil
}

func (in *instance) write(ctx context.Context, s string) (uint64, error) {
	res, err := in.alloc.Call(ctx, uint64(len(s)))
	if err != nil {
		return 0, err
	}
	if !in.mod.Memory().WriteString(uint32(res[0]), s) {
		return 0, errors.New("demesne: an argument doesn't fit the runtime's memory")
	}
	return res[0], nil
}

func (in *instance) run(ctx context.Context, fn api.Function, a, b string) ([]byte, error) {
	pa, err := in.write(ctx, a)
	if err != nil {
		return nil, err
	}
	pb, err := in.write(ctx, b)
	if err != nil {
		return nil, err
	}
	res, err := fn.Call(ctx, pa, uint64(len(a)), pb, uint64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("demesne: the runtime stopped: %w", err)
	}
	ptr, n := uint32(res[0]>>32), uint32(res[0])
	view, ok := in.mod.Memory().Read(ptr, n)
	if !ok {
		return nil, errors.New("demesne: the runtime's answer is outside its memory")
	}
	out := append([]byte(nil), view...)
	if _, err := in.free.Call(ctx, uint64(ptr), uint64(n)); err != nil {
		return nil, err
	}
	return out, nil
}

type envelope struct {
	Ok    json.RawMessage `json:"ok"`
	Error *string         `json:"error"`
}

func decode(raw []byte, out any) error {
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return fmt.Errorf("demesne: the runtime's answer isn't JSON: %w", err)
	}
	if e.Error != nil {
		return &Error{Message: *e.Error}
	}
	if err := json.Unmarshal(e.Ok, out); err != nil {
		return fmt.Errorf("demesne: the runtime's answer doesn't fit %T: %w", out, err)
	}
	return nil
}

// Call runs the runtime operation op on args, which it encodes as a JSON object, and decodes the result into out.
// The typed methods are built on it; it is exported for an operation they don't cover yet.
func (r *Runtime) Call(ctx context.Context, op string, args any, out any) error {
	in, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("demesne: %s: encode the arguments: %w", op, err)
	}
	raw, err := r.run(ctx, func(i *instance) api.Function { return i.call }, op, string(in))
	if err != nil {
		return err
	}
	return decode(raw, out)
}

// Authorize returns the policy decision point's decision for procedure under pdp, asking holds whether the caller
// holds the permission that governs it. holds is asked at most once, and only for a governed procedure.
func (r *Runtime) Authorize(ctx context.Context, pdp PDP, procedure string, holds func(perm string) bool) (Decision, error) {
	in, err := json.Marshal(pdp)
	if err != nil {
		return "", fmt.Errorf("demesne: authorize: encode the PDP: %w", err)
	}
	raw, err := r.run(context.WithValue(ctx, holdsKey{}, holds), func(i *instance) api.Function { return i.authorize }, string(in), procedure)
	if err != nil {
		return "", err
	}
	var d Decision
	return d, decode(raw, &d)
}
