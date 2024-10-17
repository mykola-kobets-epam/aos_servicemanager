// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2021 Renesas Electronics Corporation.
// Copyright (C) 2021 EPAM Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iamclient

import (
	"context"
	"sync"
	"time"

	"github.com/aosedge/aos_common/aoserrors"
	"github.com/aosedge/aos_common/aostypes"
	pb "github.com/aosedge/aos_common/api/iamanager"
	"github.com/aosedge/aos_common/utils/cryptutils"
	"github.com/aosedge/aos_common/utils/grpchelpers"
	"github.com/aosedge/aos_common/utils/pbconvert"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/aosedge/aos_servicemanager/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	iamRequestTimeout    = 30 * time.Second
	iamReconnectInterval = 10 * time.Second
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Client IAM client instance.
type Client struct {
	sync.Mutex
	*grpchelpers.IAMPublicServiceClient

	config        *config.Config
	cryptocontext *cryptutils.CryptoContext
	insecure      bool

	publicConnection    *grpc.ClientConn
	protectedConnection *grpc.ClientConn

	publicPermissionsService pb.IAMPublicPermissionsServiceClient
	permissionsService       pb.IAMPermissionsServiceClient

	tlsCertChan      <-chan *pb.CertInfo
	closeChannel     chan struct{}
	disableReconnect bool
	reconnectChannel chan struct{}

	reconnectTimer *time.Timer
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new IAM client.
func New(
	config *config.Config, cryptocontext *cryptutils.CryptoContext, insecureConn bool,
) (client *Client, err error) {
	client = &Client{
		IAMPublicServiceClient: grpchelpers.NewIAMPublicServiceClient(iamRequestTimeout),
		config:                 config,
		cryptocontext:          cryptocontext,
		insecure:               insecureConn,

		tlsCertChan:      make(<-chan *pb.CertInfo),
		closeChannel:     make(chan struct{}, 1),
		reconnectChannel: make(chan struct{}, 1),
	}

	defer func() {
		if err != nil {
			client.Close()
		}
	}()

	if err = client.openGRPCConnection(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if !insecureConn {
		if ch, err := client.SubscribeCertChanged(config.CertStorage); err != nil {
			return nil, aoserrors.Wrap(err)
		} else {
			client.tlsCertChan = ch
		}
	}

	go client.processEvents()

	return client, nil
}

// RegisterInstance registers new service instance with permissions and create secret.
func (client *Client) RegisterInstance(
	instance aostypes.InstanceIdent, permissions map[string]map[string]string,
) (secret string, err error) {
	client.Lock()
	defer client.Unlock()

	log.WithFields(log.Fields{
		"serviceID": instance.ServiceID,
		"subjectID": instance.SubjectID,
		"instance":  instance.Instance,
	}).Debug("Register instance")

	ctx, cancel := context.WithTimeout(context.Background(), iamRequestTimeout)
	defer cancel()

	reqPermissions := make(map[string]*pb.Permissions)
	for key, value := range permissions {
		reqPermissions[key] = &pb.Permissions{Permissions: value}
	}

	response, err := client.permissionsService.RegisterInstance(ctx,
		&pb.RegisterInstanceRequest{Instance: pbconvert.InstanceIdentToPB(instance), Permissions: reqPermissions})
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	return response.GetSecret(), nil
}

// UnregisterInstance unregisters service instance.
func (client *Client) UnregisterInstance(instance aostypes.InstanceIdent) (err error) {
	client.Lock()
	defer client.Unlock()

	log.WithFields(log.Fields{
		"serviceID": instance.ServiceID,
		"subjectID": instance.SubjectID,
		"instance":  instance.Instance,
	}).Debug("Unregister instance")

	ctx, cancel := context.WithTimeout(context.Background(), iamRequestTimeout)
	defer cancel()

	if _, err := client.permissionsService.UnregisterInstance(ctx,
		&pb.UnregisterInstanceRequest{Instance: pbconvert.InstanceIdentToPB(instance)}); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

// GetPermissions gets permissions by secret and functional server ID.
func (client *Client) GetPermissions(
	secret, funcServerID string,
) (instance aostypes.InstanceIdent, permissions map[string]string, err error) {
	client.Lock()
	defer client.Unlock()

	log.WithField("funcServerID", funcServerID).Debug("Get permissions")

	ctx, cancel := context.WithTimeout(context.Background(), iamRequestTimeout)
	defer cancel()

	req := &pb.PermissionsRequest{Secret: secret, FunctionalServerId: funcServerID}

	response, err := client.publicPermissionsService.GetPermissions(ctx, req)
	if err != nil {
		return instance, nil, aoserrors.Wrap(err)
	}

	return aostypes.InstanceIdent{
		ServiceID: response.GetInstance().GetServiceId(),
		SubjectID: response.GetInstance().GetSubjectId(), Instance: response.GetInstance().GetInstance(),
	}, response.GetPermissions().GetPermissions(), nil
}

// Close closes IAM client.
func (client *Client) Close() (err error) {
	client.Lock()
	defer client.Unlock()

	client.disableReconnect = true

	client.closeChannel <- struct{}{}

	if client.reconnectTimer != nil {
		client.reconnectTimer.Stop()
		client.reconnectTimer = nil
	}

	client.closeGRPCConnection()

	log.Debug("Disconnected from IAM")

	return nil
}

func (client *Client) OnConnectionLost() {
	if !client.disableReconnect {
		client.reconnectChannel <- struct{}{}
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (client *Client) openGRPCConnection() (err error) {
	log.Debug("Connecting to IAM...")

	if client.publicConnection, err = grpchelpers.CreatePublicConnection(
		client.config.IAMPublicServerURL, iamRequestTimeout, client.cryptocontext, client.insecure); err != nil {
		return err
	}

	client.RegisterIAMPublicServiceClient(client.publicConnection, client)
	client.publicPermissionsService = pb.NewIAMPublicPermissionsServiceClient(client.publicConnection)

	if client.protectedConnection, err = grpchelpers.CreateProtectedConnection(
		client.config.CertStorage, client.config.IAMProtectedServerURL, iamRequestTimeout, client.cryptocontext, client, client.insecure); err != nil {
		return err
	}

	client.permissionsService = pb.NewIAMPermissionsServiceClient(client.protectedConnection)

	return nil
}

func (client *Client) closeGRPCConnection() {
	log.Debug("Closing IAM connection...")

	if client.publicConnection != nil {
		client.publicConnection.Close()
	}

	if client.protectedConnection != nil {
		client.protectedConnection.Close()
	}

	client.WaitIAMPublicServiceClient()
}

func (client *Client) processEvents() {
	for {
		select {
		case <-client.closeChannel:
			return

		case <-client.tlsCertChan:
			client.Lock()
			client.reconnect()
			client.Unlock()

		case <-client.reconnectChannel:
			client.Lock()
			client.reconnect()
			client.Unlock()
		}
	}
}

func (client *Client) reconnect() {
	if client.disableReconnect {
		return
	}

	log.Debug("Reconnecting to IAM server...")

	client.disableReconnect = true
	client.closeGRPCConnection()

	if err := client.openGRPCConnection(); err != nil {
		log.WithField("err", err).Error("Reconnection to IAM failed")

		client.reconnectTimer = time.AfterFunc(iamReconnectInterval, func() {
			client.Lock()
			defer client.Unlock()

			client.reconnectTimer = nil

			client.reconnect()
		})
	} else {
		client.disableReconnect = false
	}
}
