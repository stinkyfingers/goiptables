package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var (
	file         *os.File
	name         = flag.String("n", "structs.go", "")
	text         = flag.String("t", "matchext.txt", "")
	category     = flag.String("c", "MatchExtensions", "")
	masterStruct []string
)

/*
This just roughly approximates structs from the doc text - requires some cleanup and pruning before using
*/

func main() {
	var err error
	flag.Parse()

	os.Remove(*name)
	file, err = os.Create(*name)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	err = begin()
	if err != nil {
		log.Fatal(err)
	}
	err = getDoc()
	if err != nil {
		log.Fatal(err)
	}

	err = master(*category)
	if err != nil {
		log.Fatal(err)
	}

}

func getDoc() error {
	f, err := os.Open(*text)
	if err != nil {
		return err
	}
	started := false

	r := bufio.NewReader(f)

	for {
		line, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		str := strings.TrimSpace(strings.TrimPrefix(string(line), "[!]"))
		if str == "" || str == "Examples:" || str == "Example:" || str == "Features:" {
			continue
		}

		// if strings.Contains(str, "--") {
		if strings.HasPrefix(str, "--") {
			// fields
			arr := strings.Split(strings.Replace(str, "[!]", "", -1), " ")
			if len(arr) < 1 {
				continue
			}

			tag := strings.TrimPrefix(arr[0], "--")
			field := strings.Replace(tag, "-", " ", -1)
			field = strings.Title(field)
			field = strings.Replace(field, " ", "", -1)
			log.Print(tag, " ", field)
			if field == "" {
				continue
			}
			writeField(field, tag)

		} else if !strings.Contains(str, " ") && !strings.Contains(str, "=") {
			// struct
			if started {
				concludeStruct()
			}
			structName := strings.Replace(string(line), "-", " ", -1)
			structName = strings.Title(strings.ToLower(structName))
			structName = strings.Replace(structName, " ", "", -1)
			err = startStruct(structName)
			if err != nil {
				return err
			}
			started = true
		}

	}
	concludeStruct()
	return nil
}

func master(name string) error {
	str := fmt.Sprintf("type %s struct {\n%s}", name, strings.Join(masterStruct, ""))
	_, err := file.WriteString(str)
	return err
}

func begin() error {
	_, err := file.WriteString("package goiptables\n")
	return err
}

func startStruct(str string) error {
	masterStruct = append(masterStruct, fmt.Sprintf("\t%s `flag:\"m\" short:\"%s\"`\n", str, strings.ToLower(str)))

	_, err := file.WriteString(fmt.Sprintf("type %s struct {\n", str))
	return err
}

func concludeStruct() error {
	_, err := file.WriteString("}\n")
	return err
}

func writeField(field, tag string) error {
	_, err := file.WriteString(fmt.Sprintf("\t%s string `short:\"%s\" long:\"%s\"`\n", field, tag, tag))
	return err
}
