package certs

import "fmt"

// Durée de vie d'un blob, un an (IDR-0038).
const dureeBlob = 365 * 24 * 3600

// DemandeBlob reprend le format de /api/generate de FGP, sans le jeton ni la
// clé, que l'opérateur ajoute à la génération. Elle n'a pas de champ logs :
// FGP ne garde alors aucune trace des requêtes, dont le corps porte la clé
// privée TLS.
type DemandeBlob struct {
	Name   string        `json:"name"`
	Target string        `json:"target"`
	Auth   string        `json:"auth"`
	Scopes []ScopeFiltre `json:"scopes"`
	TTL    int           `json:"ttl"`
}

type ScopeFiltre struct {
	Methods     []string      `json:"methods"`
	Pattern     string        `json:"pattern"`
	BodyFilters []FiltreCorps `json:"bodyFilters"`
}

type FiltreCorps struct {
	ObjectPath  string         `json:"objectPath"`
	ObjectValue []ValeurFiltre `json:"objectValue"`
}

type ValeurFiltre struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// DemandeEcriture rend la demande du blob d'écriture d'une app Scalingo : PATCH
// d'un de ses domaines, corps limité à un certificat et une clé, comme le blob
// d'écriture du pilote. Le filtre exige ces deux champs sans interdire les
// autres : le client n'envoie jamais que ceux-là.
func DemandeEcriture(region, app string) (DemandeBlob, error) {
	if !reRegion.MatchString(region) || !reApp.MatchString(app) {
		return DemandeBlob{}, fmt.Errorf("région ou app Scalingo invalide")
	}
	return DemandeBlob{
		Name:   "waf-ops certificat " + app,
		Target: "https://api." + region + ".scalingo.com",
		Auth:   "scalingo-exchange",
		Scopes: []ScopeFiltre{{
			Methods: []string{"PATCH"},
			Pattern: "/v1/apps/" + app + "/domains/*",
			BodyFilters: []FiltreCorps{
				{ObjectPath: "domain.tlscert", ObjectValue: []ValeurFiltre{
					{Type: "stringwildcard", Value: "-----BEGIN CERTIFICATE-----*"},
				}},
				// Le * de FGP couvre un caractère au moins : la seconde valeur ne
				// couvre pas une clé PKCS #8, sans préfixe avant PRIVATE KEY.
				{ObjectPath: "domain.tlskey", ObjectValue: []ValeurFiltre{
					{Type: "stringwildcard", Value: "-----BEGIN PRIVATE KEY-----*"},
					{Type: "stringwildcard", Value: "-----BEGIN *PRIVATE KEY-----*"},
				}},
			},
		}},
		TTL: dureeBlob,
	}, nil
}
