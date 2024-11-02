package plugin

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func ReadKeyOp(privateKeyPath, usr string) ([]byte, error) {
	cmd := exec.Command("op", "read", privateKeyPath)
	if usr != "" {
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
			if !(e[:5] == "HOME=" || e[:5] == "USER=" || e[:8] == "LOGNAME=") {
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
