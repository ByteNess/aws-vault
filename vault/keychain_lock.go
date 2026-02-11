package vault

const keychainLockFilenamePrefix = "aws-vault.keychain"

// KeychainLock coordinates keychain access across processes.
type KeychainLock = ProcessLock

// NewDefaultKeychainLock creates a lock in the system temp directory.
// This only coordinates processes that share the same temp dir; differing TMPDIRs/users are out of scope.
func NewDefaultKeychainLock(lockKey string) KeychainLock {
	return NewKeychainLock(defaultLockPath(keychainLockFilename(lockKey)))
}

// NewKeychainLock creates a lock at the provided path.
func NewKeychainLock(path string) KeychainLock {
	return NewFileLock(path)
}

func keychainLockFilename(lockKey string) string {
	return hashedLockFilename(keychainLockFilenamePrefix, lockKey)
}
