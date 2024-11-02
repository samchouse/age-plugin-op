package plugin

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

func ReadKeyOp(privateKeyPath, usr string) ([]byte, error) {
	usr = cleanString(usr)
	cmd := exec.Command("op", "read", privateKeyPath)

	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("could not get current user: %v", err)
	}
	if usr != "" && usr != currentUser.Username {
		user, err := user.Lookup(usr)
		if err != nil {
			return nil, fmt.Errorf("could not get user: %v", err)
		}

		uid, err := strconv.Atoi(user.Uid)
		if err != nil {
			return nil, fmt.Errorf("could not parse uid: %v", err)
		}
		gid, err := strconv.Atoi(user.Gid)
		if err != nil {
			return nil, fmt.Errorf("could not parse gid: %v", err)
		}

		cmd.Dir = user.HomeDir
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}

		env := []string{}
		for _, e := range os.Environ() {
			if !(strings.HasPrefix(e, "HOME=") || strings.HasPrefix(e, "USER=") || strings.HasPrefix(e, "LOGNAME=")) {
				env = append(env, e)
			}
		}
		cmd.Env = append(env,
			"HOME="+user.HomeDir,
			"USER="+user.Username,
			"LOGNAME="+user.Username,
		)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("could not read private key from 1Password: %v", err)
	}
	return output, nil
}

func cleanString(s string) string {
	if len(s) > 0 && unicode.IsControl(rune(s[0])) {
		return s[1:]
	}
	return s
}
