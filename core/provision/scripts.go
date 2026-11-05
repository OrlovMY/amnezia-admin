// Package provision — официальные серверные скрипты amnezia-client,
// закреплённые по ревизиям (go:embed), и безопасная подстановка переменных
// в них. Здесь только данные и чистые функции: ничего не выполняется и ни к
// чему не подключается (план БК «перенос на чистый сервер», PR 3).
//
// Скрипты — дословные копии client/server_scripts/ из
// github.com/amnezia-vpn/amnezia-client на закреплённом коммите. Вендорены
// только файлы пути установки (InstallController::setupContainer):
// install_docker, prepare_host, remove_container, build_container,
// setup_host_firewall и <папка протокола>/{Dockerfile, run_container.sh,
// configure_container.sh, start.sh}. Клиентские шаблоны (template.conf,
// template.json) к установке не относятся и не вендорены.
package provision

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed all:scripts
var embedded embed.FS

// Revision — закреплённая ревизия скриптов amnezia-client.
type Revision struct {
	ID     string // имя каталога в scripts/ и ключ во всех таблицах
	Tag    string // релизный тег; "" — ревизия не релизная (ветка dev)
	Commit string // полный SHA коммита amnezia-client
	// Files — ЗАКРЫТЫЙ список файлов ревизии и SHA-256 каждого. Файл вне
	// списка или с другой суммой — ошибка, а не «как-нибудь сойдёт».
	Files map[string]string
}

// RevDev94b51df — ревизия, по которой в core разобраны форматы
// (core.amneziaClientRevision, «amnezia-client dev 94b51df»).
const RevDev94b51df = "dev-94b51df"

// Rev5106 — последний релизный тег amnezia-client на 05.11.2026
// (gh api repos/amnezia-vpn/amnezia-client/releases/latest → 5.1.0.6).
const Rev5106 = "5.1.0.6"

// revisions — закрытый список. Порядок ключей — RevisionIDs.
var revisions = map[string]Revision{
	RevDev94b51df: {
		ID:     RevDev94b51df,
		Tag:    "",
		Commit: "94b51df24790bf52427afe82d81c87a95460bdfd",
		Files: map[string]string{
			"build_container.sh":                "e6ec608410317f0871b74fd672cf66133ab82642824259dd80c4bd08ca69fdfb",
			"install_docker.sh":                 "74e41f2beff86a6c5b4419392b73edeb15596833b742b29ec382024f3ef1d2dc",
			"prepare_host.sh":                   "7e23e8d1fb9265d2423f378f06a1a7b91646e5d78e8b41f0baeeccbf6cf4293b",
			"setup_host_firewall.sh":            "b7a36f34e09bd86cfcbc40d0781cd1319afd5c833c057236b61c6241312396d6",
			"remove_container.sh":               "d680bc941b58b5dec610a0a1f88158978c986cf08a56a1ff302b6307c06b2bd6",
			"awg/Dockerfile":                    "9a2330227d9950f20c03022885710d5982ed6e13c80dc4acefb0b0526c30b60a",
			"awg/configure_container.sh":        "2da679ca4c65e51ae42279fc2b14f948d8736f1b8d0ccdcac7da8f63a8f159b6",
			"awg/run_container.sh":              "a7ebca174111894cc17c00950c2c386b5f18bb5fc9ccdfd056b95584e0c70332",
			"awg/start.sh":                      "25410e31cd6cdaff9fe5ab9440526693395083018392b9f805a4d1c45a29d89c",
			"awg_legacy/Dockerfile":             "6210d306538724f1f089cb164aa4074f9a041fe2a68d8335bf0e2083193036b5",
			"awg_legacy/configure_container.sh": "0b1657cbe7702462518cf0313961126c12eccf091507f305ab4f8a9480e329f1",
			"awg_legacy/run_container.sh":       "a7ebca174111894cc17c00950c2c386b5f18bb5fc9ccdfd056b95584e0c70332",
			"awg_legacy/start.sh":               "a6980bdd9568b09e7ff1d974bcb18eac163f14ca31a728c74783b51565bb9844",
			"wireguard/Dockerfile":              "8fbc914f8632eea1c5011d93d32366026a3e39a67d6757dffd44d771a0eed630",
			"wireguard/configure_container.sh":  "8f70e3200b6f2863416b5d394366f9ac95889b21bc8764c304504db0b2df95c7",
			"wireguard/run_container.sh":        "948e806dd42c7f84955eca3b51260c3d540e323c3581fa5cb69e2642d3aedc5b",
			"wireguard/start.sh":                "e46c0eb9480bb1bd53a4319664cd1d76c66656c266d735457ba1009512129fee",
			"xray/Dockerfile":                   "86fa5539e124084124a0ccd0fa80391abe6005656531f5d18a7d023415c668be",
			"xray/configure_container.sh":       "1341c321dfadfe56afa228ab9f91f2f84612870982063b954ab8b5be7cf87f11",
			"xray/run_container.sh":             "cf322019d34272b0185ccc138f000866673ac2243866b14c5d57ec7e021cf2a6",
			"xray/start.sh":                     "026b840844898960fcab2c398c7de18bb2a491b28ff8042692b713d50a21d77e",
		},
	},
	Rev5106: {
		ID:     Rev5106,
		Tag:    "5.1.0.6",
		Commit: "ac175c8a8147cfe56f98c8372ec17ea2ba00bb02",
		Files: map[string]string{
			"build_container.sh":                "e6ec608410317f0871b74fd672cf66133ab82642824259dd80c4bd08ca69fdfb",
			"install_docker.sh":                 "74e41f2beff86a6c5b4419392b73edeb15596833b742b29ec382024f3ef1d2dc",
			"prepare_host.sh":                   "7e23e8d1fb9265d2423f378f06a1a7b91646e5d78e8b41f0baeeccbf6cf4293b",
			"setup_host_firewall.sh":            "52e170f45e6ba27a8eedb4a3cf78f8abbaf0a279c71bd3a7276807db8456c644",
			"remove_container.sh":               "d680bc941b58b5dec610a0a1f88158978c986cf08a56a1ff302b6307c06b2bd6",
			"awg/Dockerfile":                    "9a2330227d9950f20c03022885710d5982ed6e13c80dc4acefb0b0526c30b60a",
			"awg/configure_container.sh":        "2da679ca4c65e51ae42279fc2b14f948d8736f1b8d0ccdcac7da8f63a8f159b6",
			"awg/run_container.sh":              "a7ebca174111894cc17c00950c2c386b5f18bb5fc9ccdfd056b95584e0c70332",
			"awg/start.sh":                      "25410e31cd6cdaff9fe5ab9440526693395083018392b9f805a4d1c45a29d89c",
			"awg_legacy/Dockerfile":             "6210d306538724f1f089cb164aa4074f9a041fe2a68d8335bf0e2083193036b5",
			"awg_legacy/configure_container.sh": "0b1657cbe7702462518cf0313961126c12eccf091507f305ab4f8a9480e329f1",
			"awg_legacy/run_container.sh":       "a7ebca174111894cc17c00950c2c386b5f18bb5fc9ccdfd056b95584e0c70332",
			"awg_legacy/start.sh":               "a6980bdd9568b09e7ff1d974bcb18eac163f14ca31a728c74783b51565bb9844",
			"wireguard/Dockerfile":              "8fbc914f8632eea1c5011d93d32366026a3e39a67d6757dffd44d771a0eed630",
			"wireguard/configure_container.sh":  "8f70e3200b6f2863416b5d394366f9ac95889b21bc8764c304504db0b2df95c7",
			"wireguard/run_container.sh":        "948e806dd42c7f84955eca3b51260c3d540e323c3581fa5cb69e2642d3aedc5b",
			"wireguard/start.sh":                "e46c0eb9480bb1bd53a4319664cd1d76c66656c266d735457ba1009512129fee",
			"xray/Dockerfile":                   "b736ea3a0513742740fde36525b1510bacb6275f6c5cbd4bddc6fbfae70dcda8",
			"xray/configure_container.sh":       "c537a921cd9ec167c1aad17d5dd01d1fe65e3d25db7b06ea650d9cc256560061",
			"xray/run_container.sh":             "c8d10824046f62090a6b89890550bcd5490ed26ba1e53cd9275ab9e441838935",
			"xray/start.sh":                     "026b840844898960fcab2c398c7de18bb2a491b28ff8042692b713d50a21d77e",
		},
	},
}

// RevisionIDs — закреплённые ревизии в порядке возрастания.
func RevisionIDs() []string {
	ids := make([]string, 0, len(revisions))
	for id := range revisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// LookupRevision — ревизия по ID; ok=false — такой ревизии не закреплено.
func LookupRevision(id string) (Revision, bool) {
	r, ok := revisions[id]
	return r, ok
}

// readVerified читает файл ревизии из fsys и сверяет SHA-256 с закреплённой.
// Файл вне закрытого списка или с другой суммой — ошибка: подменённый скрипт
// не уходит дальше ни при каких условиях.
func readVerified(fsys fs.FS, rev, file string) ([]byte, error) {
	r, ok := revisions[rev]
	if !ok {
		return nil, fmt.Errorf("ревизия скриптов %q не закреплена", rev)
	}
	want, ok := r.Files[file]
	if !ok {
		return nil, fmt.Errorf("файл %q не входит в закрытый список ревизии %s", file, rev)
	}
	data, err := fs.ReadFile(fsys, "scripts/"+rev+"/"+file)
	if err != nil {
		return nil, fmt.Errorf("файл %s/%s не прочитан: %w", rev, file, err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("файл %s/%s: SHA-256 %s не совпадает с закреплённой %s", rev, file, got, want)
	}
	return data, nil
}

// Script — сверенный по SHA-256 текст файла ревизии без подстановки.
func Script(rev, file string) ([]byte, error) {
	return readVerified(embedded, rev, file)
}

// verifyTree сверяет дерево fsys с закрытым списком: каждый файл каждой
// ревизии на месте с верной суммой, и нет ни одного лишнего файла.
func verifyTree(fsys fs.FS) error {
	for _, id := range RevisionIDs() {
		for f := range revisions[id].Files {
			if _, err := readVerified(fsys, id, f); err != nil {
				return err
			}
		}
	}
	return fs.WalkDir(fsys, "scripts", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		for _, id := range RevisionIDs() {
			pre := "scripts/" + id + "/"
			if len(p) > len(pre) && p[:len(pre)] == pre {
				if _, ok := revisions[id].Files[p[len(pre):]]; ok {
					return nil
				}
			}
		}
		return fmt.Errorf("лишний файл %s вне закрытого списка", p)
	})
}

// VerifyAll — сверка всех вендоренных файлов (вызывать перед установкой).
func VerifyAll() error { return verifyTree(embedded) }
