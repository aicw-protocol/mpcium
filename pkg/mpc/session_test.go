package mpc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockKVStore struct {
	deleted   []string
	deleteErr map[string]error
}

func (m *mockKVStore) Put(string, []byte) error { return nil }

func (m *mockKVStore) Get(string) ([]byte, error) { return nil, nil }

func (m *mockKVStore) Delete(key string) error {
	if err, ok := m.deleteErr[key]; ok {
		return err
	}
	m.deleted = append(m.deleted, key)
	return nil
}

func (m *mockKVStore) Close() error { return nil }

func (m *mockKVStore) Backup() error { return nil }

func TestDeleteOldShareData_VersionedAndLegacy(t *testing.T) {
	mock := &mockKVStore{}
	s := &session{
		walletID: "wallet-1",
		kvstore:  mock,
		composeKey: func(id string) string {
			return "eddsa:" + id
		},
	}

	s.deleteOldShareData("wallet-1", 2)

	assert.Equal(t, []string{"eddsa:wallet-1_v2", "eddsa:wallet-1"}, mock.deleted)
}

func TestDeleteOldShareData_LegacyOnly(t *testing.T) {
	mock := &mockKVStore{}
	s := &session{
		walletID: "wallet-1",
		kvstore:  mock,
		composeKey: func(id string) string {
			return "eddsa:" + id
		},
	}

	s.deleteOldShareData("wallet-1", 0)

	assert.Equal(t, []string{"eddsa:wallet-1"}, mock.deleted)
}

func TestDeleteOldShareData_DeleteErrorDoesNotPanic(t *testing.T) {
	mock := &mockKVStore{
		deleteErr: map[string]error{
			"eddsa:wallet-1": errors.New("delete failed"),
		},
	}
	s := &session{
		walletID: "wallet-1",
		kvstore:  mock,
		composeKey: func(id string) string {
			return "eddsa:" + id
		},
	}

	assert.NotPanics(t, func() {
		s.deleteOldShareData("wallet-1", 0)
	})
}
