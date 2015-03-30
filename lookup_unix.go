// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build dragonfly freebsd linux netbsd openbsd solaris

package user

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func current() (*User, error) {
	return lookupUnix(syscall.Getuid(), "", false)
}

func lookup(username string) (*User, error) {
	return lookupUnix(-1, username, true)
}

func lookupId(uid string) (*User, error) {
	i, e := strconv.Atoi(uid)
	if e != nil {
		return nil, e
	}
	return lookupUnix(i, "", false)
}

// username:password:uid:gid:info:home:shell
func lookupUnix(uid int, username string, lookupByName bool) (*User, error) {
	var matchField int
	var matchString string
	if lookupByName {
		matchField = 0
		matchString = username
	} else {
		matchField = 2
		matchString = strconv.Itoa(uid)
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("user: error opening /etc/passwd: %s", err)
	}
	b := bufio.NewReader(f)
	scanner := bufio.NewScanner(b)
	for scanner.Scan() {
		line := scanner.Text()
		if line[0] == '#' {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		if fields[matchField] == matchString {
			u := &User{
				Uid:      fields[2],
				Gid:      fields[3],
				Username: fields[0],
				Name:     fields[4],
				HomeDir:  fields[5],
			}
			// The pw_gecos field isn't quite standardized.  Some docs
			// say: "It is expected to be a comma separated list of
			// personal data where the first item is the full name of the
			// user."
			if i := strings.Index(u.Name, ","); i >= 0 {
				u.Name = u.Name[:i]
			}
			return u, nil
		}
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("user: error reading from /etc/passwd: %s", err)
	}
	return nil, fmt.Errorf("user: user not found: %s", matchString)
}
