package dbmon

import "testing"

func TestChApp(t *testing.T) {
	for in, want := range map[string]string{
		"morche-monitor/1 clickhouse-go/2.51.0 (lv:go/1.25; os:linux)": "morche-monitor",
		"ClickHouse client": "ClickHouse client",
		"":                  "",
	} {
		if got := chApp(in); got != want {
			t.Errorf("chApp(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEvaluateClickHouse(t *testing.T) {
	s := snap()
	s.Engine = ClickHouse
	s.Memory = &DatabaseMemory{UsedBytes: 96, LimitBytes: 100}
	s.Parts = &DatabaseParts{Database: "shop", Table: "orders", Partition: "202611", Count: 1200, DelayAt: 1000, ThrowAt: 3000}
	s.Mutations = &DatabaseMutations{Running: 1, Failed: 1, Table: "shop.orders", ID: "mutation_3.txt", Error: "Code: 6", Seconds: 30}
	got := Evaluate(EvalInput{Engine: ClickHouse, Snapshot: s})
	if c := find(t, got, "memory"); c.Level != LevelCritical {
		t.Errorf("memory at 96%% = %s", c.Level)
	}
	if c := find(t, got, "parts"); c.Level != LevelWarning {
		t.Errorf("parts past parts_to_delay_insert = %s (%s)", c.Level, c.Reason)
	}
	if c := find(t, got, "mutations"); c.Level != LevelWarning {
		t.Errorf("a failing mutation = %s", c.Level)
	}
	for _, id := range []string{"long_transactions", "blocking", "idle_in_transaction", "id_columns"} {
		if has(got, id) {
			t.Errorf("ClickHouse has no %s check", id)
		}
	}
	s.Parts.Count = 3000
	if c := find(t, Evaluate(EvalInput{Engine: ClickHouse, Snapshot: s}), "parts"); c.Level != LevelCritical {
		t.Errorf("parts at parts_to_throw_insert = %s", c.Level)
	}
}
