package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

//go:embed setup.ps1
var setupScript string

//go:embed netbook_key.pub
var publicKey string

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--self-test" {
		if err := configure("SelfTest", os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 1 {
		if err := elevate(); err != nil {
			fmt.Println(err)
			fmt.Println("Press Enter to close.")
			fmt.Scanln()
		}
		return
	}

	input := bufio.NewReader(os.Stdin)
	executable, err := os.Executable()
	if err == nil {
		err = runSetup(executable, input)
	}
	if err != nil {
		fmt.Println(err)
		fmt.Println("Press Enter to close.")
		input.ReadString('\n')
	}
}

// runSetup records the current run beside the executable, regardless of its working directory.
func runSetup(executable string, input *bufio.Reader) error {
	path := filepath.Join(filepath.Dir(executable), "SSH-connection.txt")
	report, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("could not create the report beside the executable: %w", err)
	}
	defer report.Close()
	fmt.Println("Connection report:", path)

	output := io.MultiWriter(os.Stdout, report)
	if err := configure("Start", output); err != nil {
		fmt.Fprintln(output, "Setup failed:", err)
	}
	if err := report.Sync(); err != nil {
		fmt.Println("Could not save the connection report:", err)
	}
	for {
		fmt.Print("\n[D] Disable SSH access    [Enter] Close window: ")
		answer, err := input.ReadString('\n')
		if err != nil || strings.TrimSpace(answer) == "" {
			return nil
		}
		if strings.EqualFold(strings.TrimSpace(answer), "d") {
			if err := configure("Stop", output); err != nil {
				fmt.Fprintln(output, "Could not disable SSH:", err)
			}
		}
	}
}

// elevate opens a separate administrator console through the Windows UAC prompt.
func elevate() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	args, _ := syscall.UTF16PtrFromString("--setup")
	shellExecute := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	result, _, callErr := shellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(args)), 0, 1)
	if result <= 32 {
		return fmt.Errorf("could not open the administrator console (code %d): %v", result, callErr)
	}
	return nil
}

func configure(action string, output io.Writer) error {
	key := strings.Fields(publicKey)
	if len(key) < 2 || key[0] != "ssh-ed25519" {
		return fmt.Errorf("embedded SSH public key is invalid")
	}
	script := "$action = '" + action + "'\n$key = 'ssh-ed25519 " + key[1] + "'\n" + setupScript
	command, err := encodeScript(script)
	if err != nil {
		return err
	}
	powershell := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if os.Getenv("PROCESSOR_ARCHITEW6432") != "" {
		powershell = filepath.Join(os.Getenv("SystemRoot"), "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	cmd := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", command)
	cmd.Stdin = os.Stdin
	cmd.Stdout, cmd.Stderr = output, output
	return cmd.Run()
}

// encodeScript compresses the script to fit the Windows process command-line limit.
// PowerShell expands it in memory so standard input remains available for confirmation.
func encodeScript(script string) (string, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := io.WriteString(writer, script); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	bootstrap := `
$data = [Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString(compressed.Bytes()) + `')
$memory = [IO.MemoryStream]::new($data)
$gzip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Decompress)
$reader = [IO.StreamReader]::new($gzip)
try { $source = $reader.ReadToEnd() } finally { $reader.Dispose() }
& ([scriptblock]::Create($source))
`
	units := utf16.Encode([]rune(bootstrap))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	command := base64.StdEncoding.EncodeToString(encoded)
	if len(command) > 32000 {
		return "", fmt.Errorf("compressed setup script exceeds the Windows command-line limit")
	}
	return command, nil
}
