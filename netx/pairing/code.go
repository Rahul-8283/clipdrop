// Package pairing implements out-of-band device pairing using human-readable
// phonetic codes, PAKE cryptographic key agreement, and encrypted credential exchange.
package pairing

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// codePattern matches the canonical NNNN-word-word pairing code format.
var codePattern = regexp.MustCompile(`^[0-9]{4}-[a-z]+-[a-z]+$`)

// wordList contains 256 common, phonetic, unambiguous English words
// representing animals, colors, and natural elements.
var wordList = []string{
	"amber", "anchor", "badger", "bamboo", "banner", "baron", "beacon", "beetle",
	"birch", "bison", "blaze", "bloom", "breeze", "bronze", "brook", "cactus",
	"canyon", "castle", "cedar", "cinder", "cliff", "clover", "cobalt", "comet",
	"copper", "coral", "crane", "crater", "creek", "crest", "crystal", "cypress",
	"dagger", "dancer", "dawn", "delta", "desert", "dolphin", "dragon", "drift",
	"dune", "eagle", "ember", "falcon", "fathom", "feather", "fern", "finch",
	"flame", "flint", "forest", "fossil", "fox", "frost", "garnet", "geyser",
	"glacier", "glade", "glen", "glow", "granite", "grove", "gull", "harbor",
	"haven", "hawk", "hazel", "heather", "heron", "hickory", "horizon", "hound",
	"hunter", "icicle", "iguana", "indigo", "island", "ivy", "jaguar", "jasper",
	"javelin", "juniper", "kelp", "kestrel", "lagoon", "lark", "laurel", "leaf",
	"leopard", "lichen", "lily", "linden", "lion", "lizard", "lotus", "lunar",
	"lynx", "magpie", "mallet", "maple", "marble", "marsh", "meadow", "meteor",
	"mist", "moon", "moss", "motel", "moth", "myrtle", "nebula", "nest",
	"newt", "nickel", "nimbus", "north", "oak", "oasis", "ocean", "olive",
	"onyx", "opal", "orbit", "orca", "orchid", "osprey", "otter", "owl",
	"palm", "panther", "parrot", "pebble", "pelican", "pepper", "phoenix", "pine",
	"planet", "plover", "polar", "pond", "poppy", "prairie", "prism", "quail",
	"quartz", "quarry", "radar", "raven", "reef", "rhino", "ridge", "ripple",
	"river", "robin", "rocket", "ruby", "sable", "sage", "sailor", "salmon",
	"sand", "sapphire", "scale", "scarlet", "scout", "shadow", "shale", "shark",
	"shell", "shimmer", "sierra", "silver", "skate", "sloth", "smoke", "snow",
	"solar", "sparrow", "spear", "spider", "spire", "spring", "spruce", "star",
	"stone", "storm", "stream", "summit", "sunset", "surge", "swallow", "swan",
	"talon", "tarn", "teal", "terra", "thistle", "thorn", "thunder", "tide",
	"tiger", "timber", "titan", "topaz", "torch", "tower", "trail", "tropic",
	"tulip", "tundra", "turtle", "twilight", "valley", "vapor", "velvet", "viper",
	"violet", "vortex", "vulcan", "walrus", "wave", "willow", "wind", "wolf",
	"wombat", "wood", "wren", "yarrow", "yew", "yucca", "zenith", "zephyr",
}

// GenerateCode creates a random human-readable pairing code in NNNN-word-word format
// (e.g. 8412-amber-falcon) using crypto/rand for entropy.
func GenerateCode() (string, error) {
	// 4-digit number: 0000 - 9999
	numBig, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return "", fmt.Errorf("pairing: failed to generate random number: %w", err)
	}

	wLen := big.NewInt(int64(len(wordList)))
	idx1, err := rand.Int(rand.Reader, wLen)
	if err != nil {
		return "", fmt.Errorf("pairing: failed to generate first word: %w", err)
	}

	idx2, err := rand.Int(rand.Reader, wLen)
	if err != nil {
		return "", fmt.Errorf("pairing: failed to generate second word: %w", err)
	}

	return fmt.Sprintf("%04d-%s-%s", numBig.Int64(), wordList[idx1.Int64()], wordList[idx2.Int64()]), nil
}

// NormalizeCode trims whitespace, converts spaces to hyphens, and lowercases
// the input pairing code for tolerant user entry.
func NormalizeCode(code string) string {
	s := strings.TrimSpace(code)
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

// ValidateCodeFormat checks whether code conforms to the canonical NNNN-word-word pattern.
func ValidateCodeFormat(code string) bool {
	return codePattern.MatchString(NormalizeCode(code))
}
