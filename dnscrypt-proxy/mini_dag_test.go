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

package main

import (
	"testing"
)

const (
// A mini TEST for mini_dag
// Unlike other implement of DAG, mini_dag.go is used to transfer a given DAG into Associated Tag List (Paths)
// 'mini_dag' handles self-loop and the others fault
// However mini_dag.go is not intended to perform or navigate on hierarchical data
)

var (
	g = Graph{}
)

func TestMain(m *testing.M) {
println("start testing mini_dag")
m.Run()
println("finish testing mini_dag")
}

func (g *Graph) reset() {
	g.scc = nil
	g.v = nil
	g.finalized = false
}

func TestMyMiniDAG_general(t *testing.T) {
	g.reset()
	g.AddVertex("a", 1, []string{"b", "c", "d"})
	g.AddVertex("b", 2, []string{"c", "d"})
	g.AddVertex("c", 3, []string{"d"})
	g.AddVertex("d", 4, []string{"f", "f"})
	g.AddVertex("f", 5, nil)
	if err := g.Finalize(false); err != nil {
		t.Errorf("%v", err)
	} else {
		for k,v := range g.scc {
			t.Logf("k=%s v=%v", k, v)
		}
	}
}

func TestMyMiniDAG_selfloop(t *testing.T) {
	g.reset()
	g.AddVertex("a", 1, []string{"b", "c", "d"})
	g.AddVertex("b", 2, []string{"c", "d"})
	g.AddVertex("c", 3, []string{"d"})
	g.AddVertex("d", 4, []string{"f", "f", "b"})
	g.AddVertex("f", 5, nil)
	if err := g.Finalize(false); err == nil {
		t.Errorf("expect an error")
	} else {
		t.Logf("err msg: \"%v\"", err)
	}
}


func TestMyMiniDAG_redeclare(t *testing.T) {
	g.reset()
	g.AddVertex("a", 1, []string{"b", "c", "d"})
	if err := g.AddVertex("a", 1, []string{"e", "f", "g"}); err == nil {
		t.Errorf("expect an error")
	} else {
		t.Logf("err msg: \"%v\"", err)
	}
}

func TestMyMiniDAG_dangling(t *testing.T) {
	g.reset()
	g.AddVertex("a", 1, []string{"b", "c"})
	g.AddVertex("b", 2, []string{"c", "d"})
	g.AddVertex("c", 3, []string{"d"})
	//g.AddVertex("d", 3, []string{})
	g.AddVertex("f", 5, nil)
	if err := g.Finalize(false); err == nil {
		t.Errorf("expect an error")
	} else {
		t.Logf("err msg: \"%v\"", err)
	}
}

func TestMyMiniDAG_finalized(t *testing.T) {
	g.reset()
	g.AddVertex("a", 1, []string{"b", "c", "d"})
	g.AddVertex("b", 2, []string{"c", "d"})
	g.AddVertex("c", 3, []string{"d"})
	g.AddVertex("d", 5, nil)
	if err := g.Finalize(true); err != nil {
		t.Errorf("expect no error")
	}
	if err := g.Finalize(false); err == nil {
		t.Errorf("expect an error")
	} else {
		t.Logf("err msg on calling Finalize: \"%v\"", err)
	}
	if err := g.AddVertex("foo", 3, []string{"foo"}); err == nil {
		t.Errorf("expect an error")
	} else {
		t.Logf("err msg: on calling AddVertex \"%v\"", err)
	}
}

func TestMyMiniDAG_unhandled_mistake_proofing(t *testing.T) {
	g.reset()
	g.AddVertex(" a", 1, []string{"b", "c", "d"})
	g.AddVertex("a", 1, []string{"b", "c", "d"})
	g.AddVertex("a ", 2, []string{"c", "d"})
	g.AddVertex("b", 3, []string{"d"})
	g.AddVertex("c", 3, []string{"d"})
	g.AddVertex("d", 5, nil)
	if err := g.Finalize(false); err != nil {
		t.Errorf("expect no error")
	} else {
		for k,v := range g.scc {
			t.Logf("k=%s v=%v", k, v)
		}
	}
}

