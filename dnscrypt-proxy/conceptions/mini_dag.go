// Copyright 2020 The LUCI & AZ-X Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package conceptions
//mini : import() lines = 269
//mini : go test mini_dag.go mini_dag_test.go -v
//mini : XCopy mini_dag.go and it works
import (
)

var (
	ErrFinalized = &GraphFinalizedError{}
)

// A minimal implementation of ASG or DAG (not too fast compare to direct mathematic formula on adjacency matrix)
// Since go do not provide such detailed reference design (godoc.org)
// Things must be done by myself, this's so called BoringALG
type (
	vertex struct {
		tag                        interface{}
		key                        *string    //many case: just unique name, certain case: uuid
		descendant                 []*edge    // E
		paths                      []*string
		index                      *uint
		lowlink                    *uint
		onStack                    bool
	}

	edge struct {
		tail                       *string    // key
		head                       *string    // key
	}

	Graph struct {
		scc                        map[string][]interface{}  // projection of paths {key:root, values:tags of descendants by order}
		v                          map[string]*vertex // nil after finalizing
		finalized                  bool
	}
)

type NodeRedeclarationError struct {
	name *string
}

func (e *NodeRedeclarationError) Error() string {
	return *e.name + " is redeclared"
}

type GraphFinalizedError struct {
}

func (e *GraphFinalizedError) Error() string {
	return "cannot do the operation on a finalized graph"
}

type DanglingedgeError struct {
	edge *edge
}

func (e *DanglingedgeError) Error() string {
	return *e.edge.tail + " refers to undefined " + *e.edge.head
}

type CycleError struct {
	cycle []*string
}

func (e *CycleError) Error() string {
	errStr := make([]byte, 0)
	for i, str := range e.cycle {
		if i > 0 {
			errStr = append(errStr, byte('-'))
		}
		errStr = append(errStr, []byte(*str)...)
	}
	return "path " + string(append(errStr, []byte(" is a circle")...))
}

func (g *Graph) init() {
	if g.v == nil {
		g.v = make(map[string]*vertex)
	}
	if g.scc == nil {
		g.scc = make(map[string][]interface{})
	}
}

func (g *Graph) AddVertex(name string, tag interface{}, subset []string) error {
	g.init()
	if g.finalized {
		return ErrFinalized
	}
	if _, ok := g.v[name]; ok {
		return &NodeRedeclarationError{name:&name}
	}
	descendant := make([]*edge, len(subset))
	for i, str := range subset {
		subName := str // capture range variable
		descendant[i] = &edge{tail:&name, head:&subName}
	}
	v := &vertex{key:&name, tag:tag, descendant:descendant}
	g.v[name] = v
	return nil
}

func (g *Graph) Finalize(duplicateTag bool) error {
	var err error
	goto Go
Error:
	g.scc = nil
	return err
Go:
	g.init()
	if g.finalized {
		err = ErrFinalized
		goto Error
	}
	var index uint = 0
	//'type stack' 60 hits in go internals, scattered and none of these look same, reusable
type (
	node struct {
		value interface{}
		prev *node
	}
	Stack struct {
		top *node
		length int
		Pop func() interface{}
		Push func(interface{})
	}
)
	var stack *Stack
	stack  = &Stack{nil, 0,
		func() interface{} {
			if stack.length == 0 {
				return nil
			}
			n := stack.top
			stack.top = n.prev
			stack.length--
			return n.value
		},
		func(value interface{}) {
			n := &node{value,stack.top}
			stack.top = n
			stack.length++
		},
	}
	min := func(a, b *uint) *uint {
		if *a < *b {
			return a
		}
		return b
	}
	var strongconnect func(v *vertex)
	strongconnect = func(v *vertex) {
		goto Go
Error:
		return
Go:
		idx := index // capture value variable
		v.index = &idx
		v.lowlink = &idx
		index++
		stack.Push(v)
		v.onStack = true
		paths := make([]*string, 0)
		keyList := make(map[string]interface{})
		// below contains a collection of borrowing comments of THE algorithm, in case you need read it ???
		// Consider successors of v
		for _, e := range v.descendant {
			key := *e.head // capture ref prop of range variable
			if w, ok := g.v[key]; !ok {
				err = &DanglingedgeError{edge:e}
				goto Error
			} else if w.index == nil {
				// Successor w has not yet been visited; recurse on it
				if strongconnect(w); err != nil {
					goto Error
				}
				v.lowlink = min(v.lowlink, w.lowlink)
			} else if w.onStack {
				// Successor w is in stack S and hence in the current SCC
				// If w is not on stack, then (v, w) is an edge pointing to an SCC already found and must be ignored
				// Note: The next line may look odd - but is correct.
				// It says w.index not w.lowlink; that is deliberate and from the original paper
				v.lowlink = min(v.lowlink, w.index)
			}
			addToPath := true
			if !duplicateTag {
				if _, ok := keyList[key]; ok {
					addToPath = false
				} else {
					keyList[key] = nil
				}
			}
			if addToPath {
				paths = append(paths, &key)
				for _, path := range g.v[key].paths {
					key := *path
					if !duplicateTag {
						if _, ok := keyList[key]; ok {
							continue
						}
						keyList[key] = nil
					}
					paths = append(paths, &key)
				}
			}
		}
		// If v is a root node, pop the stack and generate an SCC
		if v.lowlink == v.index {
			//start a new strongly connected component
			set := make([]*string, 0)
			for ;; {
				w := stack.Pop().(*vertex)
				w.onStack = false
				//add w to current strongly connected component
				set = append(set, w.key)
				if w == v {
					break
				}
			}
			//output the current strongly connected component
			if len(set) > 1 { //self-loop
				err = &CycleError{cycle:set}
				goto Error
			} else {
				v.paths = paths
				tags := make([]interface{}, 0)
				tags = append(tags, v.tag)
				for _, path := range v.paths {
					key := *path
					tags = append(tags, g.v[key].tag)
				}
				g.scc[*v.key] = tags
			}
		}
	}
	for _, v := range g.v {
		if v.index == nil {
			if strongconnect(v); err != nil {
				goto Error
			}
		}
	}
	g.finalized = true
	g.v = nil
	return nil
}

func (g *Graph) Tags(name string) []interface{} {
	if !g.finalized {
		return nil
	}
	return g.scc[name]
}
