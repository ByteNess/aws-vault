package prompt

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const (
	creduiFlagsAlwaysShowUI       = 0x00080
	creduiFlagsGenericCredentials = 0x40000
	creduiFlagsKeepUsername       = 0x100000
)

type creduiInfoA struct {
	cbSize         uint32
	hwndParent     uintptr
	pszMessageText *uint16
	pszCaptionText *uint16
	hbmBanner      uintptr
}

func winCredUIPrompt(mfaSerial string) (string, error) {
	captionText, err := syscall.UTF16PtrFromString("Enter MFA code for aws-vault")
	if err != nil {
		return "", err
	}
	messageText, err := syscall.UTF16PtrFromString(mfaPromptMessage(mfaSerial))
	if err != nil {
		return "", err
	}
	info := &creduiInfoA{
		hwndParent:     0,
		pszCaptionText: captionText,
		pszMessageText: messageText,
		hbmBanner:      0,
	}
	info.cbSize = uint32(unsafe.Sizeof(*info))
	passwordBuf := make([]uint16, 64)
	save := false
	flags := creduiFlagsAlwaysShowUI | creduiFlagsKeepUsername | creduiFlagsGenericCredentials
	shortSerial := strings.ReplaceAll(strings.ReplaceAll(mfaSerial, "arn:aws:iam::", ""), ":mfa", "")
	targetName, err := syscall.BytePtrFromString("aws-vault")
	if err != nil {
		return "", err
	}
	userName, err := syscall.UTF16PtrFromString(shortSerial)
	if err != nil {
		return "", err
	}

	ret, _, _ := syscall.NewLazyDLL("credui.dll").NewProc("CredUIPromptForCredentialsW").Call(
		uintptr(unsafe.Pointer(info)),
		uintptr(unsafe.Pointer(targetName)),
		0,
		0,
		uintptr(unsafe.Pointer(userName)),
		uintptr(len(shortSerial)+1),
		uintptr(unsafe.Pointer(&passwordBuf[0])),
		64,
		uintptr(unsafe.Pointer(&save)),
		uintptr(flags),
	)
	if ret != 0 {
		return "", errors.New("wincredui: call to CredUIPromptForCredentialsW failed")
	}

	return strings.TrimSpace(syscall.UTF16ToString(passwordBuf)), nil
}

func init() {
	Methods["wincredui"] = winCredUIPrompt
}
