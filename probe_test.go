package dash

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ProbeBudgetIsPerFileNotPerOpen(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	budget := newProbeBudget(150)

	first := newProbeReader(bytes.NewReader(data), 1000, budget)
	assert.NotNil(t, first.readAt(0, 100), "first read fits")
	assert.NotNil(t, first.readAt(50, 100), "overlap only charges the new 50 bytes")

	// a fresh reader over the same file sees the same accounting
	second := newProbeReader(bytes.NewReader(data), 1000, budget)
	assert.Nil(t, second.readAt(500, 100), "nothing left for a new region")
	assert.NotNil(t, second.readAt(0, 150), "already covered bytes stay free")
	assert.EqualValues(t, 0, budget.remaining)

	// tail reads charge only what they touch
	tail := newProbeReader(bytes.NewReader(data), 1000, newProbeBudget(30))
	assert.NotNil(t, tail.readTail(20))
	assert.Nil(t, tail.readTail(60), "the extra 40 bytes exceed the budget")
}
