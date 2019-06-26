// +build darwin

/*
Copyright 2016 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hyperkit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/code-ready/machine/libmachine/drivers"
	"github.com/code-ready/machine/libmachine/log"
	"github.com/code-ready/machine/libmachine/mcnutils"
	"github.com/code-ready/machine/libmachine/state"
	hyperkit "github.com/moby/hyperkit/go"
	pkgdrivers "github.com/code-ready/crc-driver-hyperkit/pkg/drivers"
)

const (
	pidFileName     = "hyperkit.pid"
	machineFileName = "hyperkit.json"
	permErr         = "%s needs to run with elevated permissions. " +
		"Please run the following command, then try again: " +
		"sudo chown root:wheel %s && sudo chmod u+s %s"
)

/*
var (
	kernelRegexp       = regexp.MustCompile(`(vmlinu[xz]|bzImage)[\d]*`)
	kernelOptionRegexp = regexp.MustCompile(`(?:\t|\s{2})append\s+([[:print:]]+)`)
)
*/

type Driver struct {
	*drivers.BaseDriver
	*pkgdrivers.CommonDriver
	CPU            int
	Memory         int
	DiskPath       string
	DiskPathURL    string
	Cmdline        string // kernel commandline
/*
	NFSShares      []string
	NFSSharesRoot  string
*/
	UUID           string
	BootKernel string
	BootInitrd string
	Initrd     string
	Vmlinuz    string
}

func NewDriver(hostName, storePath string) *Driver {
	return &Driver{
		BaseDriver: &drivers.BaseDriver{
			SSHUser: DefaultSSHUser,
		},
		CommonDriver: &pkgdrivers.CommonDriver{},
	}
}

// PreCreateCheck is called to enforce pre-creation steps
func (d *Driver) PreCreateCheck() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	if syscall.Geteuid() != 0 {
		return fmt.Errorf(permErr, filepath.Base(exe), exe, exe)
	}

	return nil
}

/* TODO: Get rid of this, have a per-machine driver GetStoragePoolPath() or something,
 * and directly call mcnutils.CopyFile
 * do not hardcode crc.disk here, it's making assumptions about B2dUtils
 * cf BaseDriver.ResolveStorePath()
 */
func (d *Driver) Create() error {

/* Obsolete, done in generic code now?
	log.Debugf("Extracting system bundle...")
	err := bundle.Extract(d.BundlePath, d.ResolveStorePath("."))
	if err != nil {
		return err
	}
*/

	b2dutils := mcnutils.NewB2dUtils(d.StorePath)
	if err := b2dutils.CopyDiskToMachineDir(d.DiskPathURL, d.MachineName); err != nil {
		return err
	}
	d.DiskPath = d.ResolveStorePath("crc.disk")

	// TODO: handle different disk types.
/*
	if err := pkgdrivers.MakeDiskImage(d.BaseDriver, d.Boot2DockerURL, d.DiskSize); err != nil {
		return errors.Wrap(err, "making disk image")
	}
	diskPath := d.ResolveStorePath(d.DiskPathURL)
	if err := d.extractKernel(diskPath); err != nil {
		return err
	}
*/

	return d.Start()
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return DriverName
}

// GetSSHHostname returns hostname for use with ssh
func (d *Driver) GetSSHHostname() (string, error) {
	return d.IPAddress, nil
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	return "", nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	pid := d.getPid()
	if pid == 0 {
		return state.Stopped, nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return state.Error, err
	}

	// Sending a signal of 0 can be used to check the existence of a process.

// Not possible to do this with the hyperkit process as it's running SUID so
// that vmnet can work
/*
	if err := p.Signal(syscall.Signal(0)); err != nil {
		return state.Stopped, nil
	}
*/

	if p == nil {
		return state.Stopped, nil
	}
	return state.Running, nil
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	return d.sendSignal(syscall.SIGKILL)
}

// Remove a host
func (d *Driver) Remove() error {
	s, err := d.GetState()
	if err != nil || s == state.Error {
		log.Infof("Error checking machine status: %s, assuming it has been removed already", err)
	}
	if s == state.Running {
		if err := d.Stop(); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) Restart() error {
	return pkgdrivers.Restart(d)
}

// Start a host
func (d *Driver) Start() error {
	h, err := hyperkit.New("", "", d.ResolveStorePath(d.MachineName))
	if err != nil {
		return err
	}

	// TODO: handle the rest of our settings.
	h.Kernel = d.ResolveStorePath(d.Vmlinuz)
	h.Initrd =d.ResolveStorePath(d.Initrd)
	h.VMNet = true
//	h.ISOImages = []string{d.ResolveStorePath(isoFilename)}
	h.Console = hyperkit.ConsoleFile
	h.CPUs = d.CPU
	h.Memory = d.Memory
	h.UUID = d.UUID

	log.Infof("Using UUID %s", h.UUID)
	mac, err := GetMACAddressFromUUID(h.UUID)
	if err != nil {
		return err
	}

	// Need to strip 0's
	mac = trimMacAddress(mac)
	log.Infof("Generated MAC %s", mac)
	h.Disks = []hyperkit.DiskConfig{
		{
			Path:   fmt.Sprintf("file://%s", d.DiskPath),
			//Size:   d.DiskSize,
			Driver: "virtio-blk",
			Format: "qcow",
		},
	}
	log.Infof("Starting with cmdline: %s", d.Cmdline)
	if err := h.Start(d.Cmdline); err != nil {
		return err
	}

	getIP := func() error {
		var err error
		d.IPAddress, err = GetIPAddressByMACAddress(mac)
		if err != nil {
			return &RetriableError{Err: err}
		}
		return nil
	}

	if err := RetryAfter(30, getIP, 2*time.Second); err != nil {
		return fmt.Errorf("IP address never found in dhcp leases file %v", err)
	}

	return nil
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	//d.cleanupNfsExports()
	return d.sendSignal(syscall.SIGTERM)
}

/*
func (d *Driver) extractKernel(isoPath string) error {
	log.Debugf("Mounting %s", isoFilename)

	volumeRootDir := d.ResolveStorePath(isoMountPath)
	err := hdiutil("attach", d.ResolveStorePath(isoFilename), "-mountpoint", volumeRootDir)
	if err != nil {
		return err
	}
	defer func() error {
		log.Debugf("Unmounting %s", isoFilename)
		return hdiutil("detach", volumeRootDir)
	}()

	log.Debugf("Extracting Kernel Options...")
	if err := d.extractKernelOptions(); err != nil {
		return err
	}

	if d.BootKernel == "" && d.BootInitrd == "" {
		filepath.Walk(volumeRootDir, func(path string, f os.FileInfo, err error) error {
			if kernelRegexp.MatchString(path) {
				d.BootKernel = path
				_, d.Vmlinuz = filepath.Split(path)
			}
			if strings.Contains(path, "initrd") {
				d.BootInitrd = path
				_, d.Initrd = filepath.Split(path)
			}
			return nil
		})
	}
	
	if  d.BootKernel == "" || d.BootInitrd == "" {
		err := fmt.Errorf("==== Can't extract Kernel and Ramdisk file ====")
		return err
		}

	dest := d.ResolveStorePath(d.Vmlinuz)
	log.Debugf("Extracting %s into %s", d.BootKernel, dest)
	if err := mcnutils.CopyFile(d.BootKernel, dest); err != nil {
		return err
	}

	dest = d.ResolveStorePath(d.Initrd)
	log.Debugf("Extracting %s into %s", d.BootInitrd, dest)
	if err := mcnutils.CopyFile(d.BootInitrd, dest); err != nil {
		return err
	}

	return nil
}

func (d *Driver) setupNFSShare() error {
	user, err := user.Current()
	if err != nil {
		return err
	}

	hostIP, err := GetNetAddr()
	if err != nil {
		return err
	}

	mountCommands := fmt.Sprintf("#/bin/bash\\n")
	log.Info(d.IPAddress)

	for _, share := range d.NFSShares {
		if !path.IsAbs(share) {
			share = d.ResolveStorePath(share)
		}
		nfsConfig := fmt.Sprintf("%s %s -alldirs -mapall=%s", share, d.IPAddress, user.Username)

		if _, err := nfsexports.Add("", d.nfsExportIdentifier(share), nfsConfig); err != nil {
			if strings.Contains(err.Error(), "conflicts with existing export") {
				log.Info("Conflicting NFS Share not setup and ignored:", err)
				continue
			}
			return err
		}

		root := d.NFSSharesRoot
		mountCommands += fmt.Sprintf("sudo mkdir -p %s/%s\\n", root, share)
		mountCommands += fmt.Sprintf("sudo mount -t nfs -o noacl,async %s:%s %s/%s\\n", hostIP, share, root, share)
	}

	if err := nfsexports.ReloadDaemon(); err != nil {
		return err
	}

	writeScriptCmd := fmt.Sprintf("echo -e \"%s\" | sh", mountCommands)

	if _, err := drivers.RunSSHCommandFromDriver(d, writeScriptCmd); err != nil {
		return err
	}

	return nil
}

func (d *Driver) nfsExportIdentifier(path string) string {
	return fmt.Sprintf("minikube-hyperkit %s-%s", d.MachineName, path)
}
*/

func (d *Driver) sendSignal(s os.Signal) error {
	pid := d.getPid()
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	return proc.Signal(s)
}

func (d *Driver) getPid() int {
	pidPath := d.ResolveStorePath(machineFileName)

	f, err := os.Open(pidPath)
	if err != nil {
		log.Warnf("Error reading pid file: %s", err)
		return 0
	}
	dec := json.NewDecoder(f)
	config := hyperkit.HyperKit{}
	if err := dec.Decode(&config); err != nil {
		log.Warnf("Error decoding pid file: %s", err)
		return 0
	}

	return config.Pid
}

/*
func (d *Driver) cleanupNfsExports() {
	if len(d.NFSShares) > 0 {
		log.Infof("You must be root to remove NFS shared folders. Please type root password.")
		for _, share := range d.NFSShares {
			if _, err := nfsexports.Remove("", d.nfsExportIdentifier(share)); err != nil {
				log.Errorf("failed removing nfs share (%s): %s", share, err.Error())
			}
		}

		if err := nfsexports.ReloadDaemon(); err != nil {
			log.Errorf("failed to reload the nfs daemon: %s", err.Error())
		}
	}
}

func (d *Driver) extractKernelOptions() error {
	volumeRootDir := d.ResolveStorePath(isoMountPath)
	if d.Cmdline == "" {
		err := filepath.Walk(volumeRootDir, func(path string, f os.FileInfo, err error) error {
			if strings.Contains(path, "isolinux.cfg") {
				d.Cmdline, err = readLine(path)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		if d.Cmdline == "" {
			return errors.New("Not able to parse isolinux.cfg")
		}
	}

	log.Debugf("Extracted Options %q", d.Cmdline)
	return nil
}
*/

func (d *Driver) waitForIP() error {
	var ip string
	var err error
	mac, err := GetMACAddressFromUUID(d.UUID)
	if err != nil {
		return err
	}

	log.Infof("Waiting for VM to come online...")
	for i := 1; i <= 60; i++ {

		ip, err = GetIPAddressByMACAddress(mac)
		if err != nil {
			log.Debugf("Not there yet %d/%d, error: %s", i, 60, err)
			time.Sleep(2 * time.Second)
			continue
		}

		if ip != "" {
			log.Debugf("Got an ip: %s", ip)
			d.IPAddress = ip

			break
		}
	}

	if ip == "" {
		return fmt.Errorf("Machine didn't return an IP after 120 seconds, aborting")
	}

	// Wait for SSH over NAT to be available before returning to user
	if err := drivers.WaitForSSH(d); err != nil {
		return err
	}

	return nil
}
