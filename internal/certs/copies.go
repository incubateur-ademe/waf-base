package certs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

const (
	dossierAcme = "acme"
	// Copies gardées par VM, une par jour.
	gardees = 7
)

var (
	reCopie      = regexp.MustCompile(`^acme-[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$`)
	reTemporaire = regexp.MustCompile(`^\.acme-[0-9]{4}-[0-9]{2}-[0-9]{2}\.json\..+$`)
)

// Âge au-delà duquel un fichier temporaire est le reste d'un passage interrompu.
const orphelin = time.Hour

// sauver écrit la copie du jour de la VM sous <état>/acme/<vm>/, en 0600 dans
// des dossiers en 0700, puis ne garde que les 7 plus récentes. Un second
// passage le même jour remplace la copie du jour.
func sauver(state, vm string, now time.Time, b []byte) (string, error) {
	if !reVM.MatchString(vm) {
		return "", fmt.Errorf("nom de VM %q hors de [a-z0-9]{1,16}", assaini(vm))
	}
	racine := filepath.Join(state, dossierAcme)
	dir := filepath.Join(racine, vm)
	for _, d := range []string{racine, dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return "", err
		}
	}
	path := filepath.Join(dir, "acme-"+jour(now)+".json")
	if err := writeAtomic(path, b, 0o600); err != nil {
		return "", err
	}
	return path, purger(dir)
}

// purger retire les copies au-delà des 7 plus récentes, et les fichiers
// temporaires d'une écriture interrompue (arrêt brutal entre la création et le
// renommage), qui portent les mêmes clés. Les fichiers d'un autre nom restent.
func purger(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var copies []string
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		if reCopie.MatchString(e.Name()) {
			copies = append(copies, e.Name())
			continue
		}
		// Un délai laisse en paix l'écriture d'un passage lancé en même temps.
		if reTemporaire.MatchString(e.Name()) {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > orphelin {
				if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
					return err
				}
			}
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(copies)))
	for _, n := range copies[min(len(copies), gardees):] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			return err
		}
	}
	return nil
}

// writeAtomic écrit dans un fichier temporaire du même dossier, puis renomme :
// un passage interrompu ne laisse pas de copie à moitié écrite.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
