package dash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Blacklist(t *testing.T) {
	assert := assert.New(t)
	assert.False(isBlacklistedExt("game/Game.exe"))
	assert.False(isBlacklistedExt("game/LaunchGame.bat"))
	assert.False(isBlacklistedExt("game/game"))
	assert.False(isBlacklistedExt("game/game.x86"))
	assert.False(isBlacklistedExt("game/game.x86_64"))

	assert.True(isBlacklistedExt("game/maps/random.umap"))
	assert.True(isBlacklistedExt("libs/x86_64/libSDL.so"))
	assert.True(isBlacklistedExt("libs/x86_64/libSDL.so.2"))
	assert.True(isBlacklistedExt("libs/x86_64/libSDL.so.2.0.0"))
}
