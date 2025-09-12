package secrets

type Tokens struct {
	GitHub []string
}

func Load() Tokens {
	return Tokens{GitHub: nil}
}
