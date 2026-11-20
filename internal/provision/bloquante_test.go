package provision

import (
	"fmt"
	"testing"
)

func TestBloquante(t *testing.T) {
	absente, vide := shared{}, shared{exists: true, known: true, empty: true}
	for _, n := range []string{
		absente.opsAction("WAF_BASE") + ", puis relancer provision ; sans elle, tout build échoue",
		vide.opsAction("EDGE_SECRET_X") + ", puis redéployer l'app",
		fmt.Sprintf("%s : référence orpheline, %s", "WAF_EDGE_SECRET", "wafgen run refuserait de démarrer"),
	} {
		if !Bloquante(n) {
			t.Fatalf("note bloquante non reconnue : %q", n)
		}
	}
	for _, n := range []string{"variable hors liste conservée : X", "WAF_BASE : la base des apps de la VM 1 passe de a à b au prochain build"} {
		if Bloquante(n) {
			t.Fatalf("note ordinaire reconnue bloquante : %q", n)
		}
	}
}
