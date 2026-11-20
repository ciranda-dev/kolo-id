package koloid

// Person keys of the eight official 24-word BIP-39 vectors (empty passphrase) at m/1802464367'/0'/0'.
// Each public key was derived by three independent implementations that agree: a pure-Python SLIP-0010 written
// separately from this code, and two npm packages for BIP-39 and SLIP-0010. None is a dependency of this module.
var personKnownAnswers = []struct{ phrase, person string }{
	{"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"47cdf056f7b1f44a3ecdb970816f20df997086219ac64b79d9d706bf5984e8c6"},
	{"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"a6025f73c1cb63a1e42eda4f817cd53aa83645fa57fa5e2566928b7bbf53d5a8"},
	{"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"7acf4b8726c894a7b50c478a0431094349e99afdc36767e04a938480668d5d7d"},
	{"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"5dd851d0ba29fabcd56f1b73765a7b70bfd7d3371921b53dca513adceb8029fd"},
	{"hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
		"bdf78375d0c83c15b455c234e27beb3693168f1d0880e7a1dea8f69e1f076784"},
	{"panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
		"26d657d2a6d3cd5b855c390f3c571ec18fdc4d34ba33891e7daac6ffc274b954"},
	{"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
		"471b51d6f9c5a677a86038db54e8aad25735268626d564185daf053172329c46"},
	{"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
		"0c2f1885795dc66c3fef407e731a992d79f70df5e6c1cd856041e9c3c211c88c"},
}
