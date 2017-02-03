package passwd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	// register hashing algorithms
	"github.com/palourde/crypt"
	_ "github.com/palourde/crypt/apr1_crypt"
	_ "github.com/palourde/crypt/md5_crypt"
	_ "github.com/palourde/crypt/sha256_crypt"
	_ "github.com/palourde/crypt/sha512_crypt"
)

const (
	passwdPath = "/etc/passwd"
	shadowPath = "/etc/shadow"
)

type Entry struct {
	Username     string
	PasswordHash string
	Uid          int
	Gid          int
	Comment      string
	Homedir      string
	Shell        string
}

func GetEntry(username string) (*Entry, error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var line string
	for scanner.Scan() {
		s := scanner.Text()
		if strings.HasPrefix(s, username) {
			line = s
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// no such user
	if line == "" {
		return nil, nil
	}

	fields := strings.Split(line, ":")
	if len(fields) != 7 {
		return nil, fmt.Errorf("bad passwd entry: want 7 fields, got %d", len(fields))
	}
	pwHash := fields[1]
	if pwHash == "x" {
		pwHash, err = getShadow(username)
		if err != nil {
			return nil, fmt.Errorf("get shadow: %v", err)
		}
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, fmt.Errorf("error parsing uid: %v", err)
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, fmt.Errorf("error parsing gid: %v", err)
	}
	return &Entry{
		Username:     fields[0],
		PasswordHash: pwHash,
		Uid:          uid,
		Gid:          gid,
		Comment:      fields[4],
		Homedir:      fields[5],
		Shell:        fields[6],
	}, nil
}

func getShadow(username string) (string, error) {
	f, err := os.Open(shadowPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var line string
	for scanner.Scan() {
		s := scanner.Text()
		if strings.HasPrefix(s, username) {
			line = s
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	// no such user
	if line == "" {
		return "", nil
	}

	fields := strings.Split(line, ":")
	if len(fields) < 2 {
		return "", fmt.Errorf("bad shadow entry: want 2 or more fields, got %d", len(fields))
	}

	return fields[1], nil
}

func (e *Entry) Authenticate(password string) bool {
	c, err := crypt.NewFromHash(e.PasswordHash)
	if err != nil {
		return false
	}
	return c.Verify(e.PasswordHash, []byte(pw)) == nil
}
