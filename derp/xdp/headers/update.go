package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	libbpfVersion = "0.6.1"
	prefix        = "libbpf-" + libbpfVersion
)

var (
	filesToExtract = map[string]struct{}{
		prefix + "/LICENSE.BSD-2-Clause":  {},
		prefix + "/src/bpf_endian.h":      {},
		prefix + "/src/bpf_helper_defs.h": {},
		prefix + "/src/bpf_helpers.h":     {},
		prefix + "/src/bpf_tracing.h":     {},
	}
)

var (
	flagDest = flag.String("dest", ".", "destination directory")
)

func main() {
	flag.Parse()

	f, err := os.CreateTemp(os.TempDir(), "libbpf")
	if err != nil {
		log.Panic(err)
	}
	defer os.Remove(f.Name())

	resp, err := http.Get(fmt.Sprintf("https://github.com/libbpf/libbpf/archive/refs/tags/v%s.tar.gz", libbpfVersion))
	if err != nil {
		log.Panic(err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		log.Panic(err)
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		log.Panic(err)
	}
	g, err := gzip.NewReader(f)
	if err != nil {
		log.Panic(err)
	}
	defer g.Close()
	t := tar.NewReader(g)

	extracted := 0
	for {
		h, err := t.Next()
		if err != nil {
			log.Panic(err)
		}
		_, ok := filesToExtract[h.Name]
		if ok {
			split := strings.Split(h.Name, "/")
			p := filepath.Join(*flagDest, split[len(split)-1])
			e, err := os.Create(p)
			if err != nil {
				log.Panic(err)
			}
			_, err = io.Copy(e, t)
			if err != nil {
				log.Panic(err)
			}
			extracted++
			if extracted == len(filesToExtract) {
				break
			}
		}
	}
}
