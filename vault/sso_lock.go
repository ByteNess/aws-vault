package vault

const defaultSSOLockFilename = "aws-vault.sso.lock"

// SSOTokenLock coordinates the SSO device flow across processes.
type SSOTokenLock = ProcessLock

// NewDefaultSSOTokenLock creates a lock in the system temp directory.
// This only coordinates processes that share the same temp dir; differing TMPDIRs/users are out of scope.
func NewDefaultSSOTokenLock() SSOTokenLock {
	return NewSSOTokenLock(defaultLockPath(defaultSSOLockFilename))
}

// NewSSOTokenLock creates a lock at the provided path.
func NewSSOTokenLock(path string) SSOTokenLock {
	return NewFileLock(path)
}
