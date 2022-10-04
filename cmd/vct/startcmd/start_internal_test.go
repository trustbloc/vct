/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms/pkg/aws"
)

func TestCreateLocalKMS(t *testing.T) {
	t.Run("fail to create Aries KMS store wrapper", func(t *testing.T) {
		km, c, err := createLocalKMS(&mockstorage.MockStoreProvider{
			FailNamespace: kms.AriesWrapperStoreName,
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{},
			},
		}, defaultMasterKeyURI)
		require.EqualError(t, err, "create Aries provider wrapper: failed to open store for name space kmsdb")
		require.Nil(t, km)
		require.Nil(t, c)
	})
	t.Run("fail to create local KMS", func(t *testing.T) {
		km, c, err := createLocalKMS(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{},
			},
		}, "")
		require.EqualError(t, err, "create kms: new: failed to create new keywrapper: "+
			"keyURI must have a prefix in form 'prefixname://'")
		require.Nil(t, km)
		require.Nil(t, c)
	})
}

func TestAWSKMSWrapper(t *testing.T) {
	wrapper := awsKMSWrapper{service: &aws.Service{}}

	keyID, handle, err := wrapper.Create("")
	require.EqualError(t, err, "key not supported ")
	require.Equal(t, "", keyID)
	require.Nil(t, handle)

	handle, err = wrapper.Get("")
	require.NoError(t, err)
	require.Equal(t, "", handle)
}
