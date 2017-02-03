// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build dragonfly freebsd linux netbsd openbsd solaris
// +build !windows,!plan9
// +build !cgo

package user

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	passwdModTime time.Time
	usersByName   map[string]*User
	usersByID     map[int]*User
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
	stat, err := os.Stat("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("user: %s", err)
	}
	if stat.ModTime() != passwdModTime || usersByID == nil {
		if err := populateMaps(); err != nil {
			return nil, fmt.Errorf("user: %s", err)
		}
		passwdModTime = stat.ModTime()
	}
	if lookupByName {
		if u, ok := usersByName[username]; ok {
			return u, nil
		} else {
			return nil, UnknownUserError(username)
		}
	} else {
		if u, ok := usersByID[uid]; ok {
			return u, nil
		} else {
			return nil, UnknownUserIdError(uid)
		}
	}
}

func populateMaps() error {
	usersByName = make(map[string]*User)
	usersByID = make(map[int]*User)
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}
	defer f.Close()
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
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return err
		}
		u := &User{
			Uid:      uid,
			Gid:      gid,
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
		usersByName[u.Username] = u
		usersByID[u.Uid] = u
	}
	return scanner.Err()
}
