package provision

import "strings"

// Bloquante dit si une note du plan demande un geste ops sans lequel un build
// échoue ou wafgen run refuse de démarrer : variable partagée à créer ou à
// remplir, référence orpheline.
func Bloquante(note string) bool {
	return strings.HasPrefix(note, "action ops : ") || strings.Contains(note, " : référence orpheline")
}
