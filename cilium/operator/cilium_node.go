// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package main

import (
	"context"

	"github.com/cilium/cilium/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	// ciliumNodeStore contains all CiliumNodes present in k8s.
	// Warning: The CiliumNodes stored in the cache are not intended to be
	// used for Update operations in k8s as some of its fields are not
	// populated.
	ciliumNodeStore cache.Store

	k8sCiliumNodesCacheSynced = make(chan struct{})
)

func startSynchronizingCiliumNodes(nodeManager allocator.NodeEventHandler) {
	log.Info("Starting to synchronize CiliumNode custom resources")

	// TODO: The operator is currently storing a full copy of the
	// CiliumNode resource, as the resource grows, we may want to consider
	// introducing a slim version of it.
	var ciliumNodeInformer cache.Controller
	ciliumNodeStore, ciliumNodeInformer = informer.NewInformer(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			v2.CNPluralName, v1.NamespaceAll, fields.Everything()),
		&v2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node := k8s.ObjToCiliumNode(obj); node != nil {
					// node is deep copied before it is stored in pkg/aws/eni
					nodeManager.Create(node)
				} else {
					log.Warningf("Unknown CiliumNode object type %T received: %+v", obj, obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldNode := k8s.ObjToCiliumNode(oldObj); oldNode != nil {
					if node := k8s.ObjToCiliumNode(newObj); node != nil {
						if oldNode.DeepEqual(node) {
							return
						}
						// node is deep copied before it is stored in pkg/aws/eni
						nodeManager.Update(node)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if node := k8s.ObjToCiliumNode(obj); node != nil {
					nodeManager.Delete(node.Name)
				}
			},
		},
		k8s.ConvertToCiliumNode,
	)

	go func() {
		cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced)
		close(k8sCiliumNodesCacheSynced)
	}()

	go ciliumNodeInformer.Run(wait.NeverStop)
}

func deleteCiliumNode(nodeManager *allocator.NodeEventHandler, name string) {
	if err := ciliumK8sClient.CiliumV2().CiliumNodes().Delete(context.TODO(), name, metav1.DeleteOptions{}); err == nil {
		log.WithField(logfields.NodeName, name).Info("Removed CiliumNode after receiving node deletion event")
	}
	if nodeManager != nil {
		(*nodeManager).Delete(name)
	}
}

type ciliumNodeUpdateImplementation struct{}

func (c *ciliumNodeUpdateImplementation) Create(node *v2.CiliumNode) (*v2.CiliumNode, error) {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Create(context.TODO(), node, metav1.CreateOptions{})
}

func (c *ciliumNodeUpdateImplementation) Get(node string) (*v2.CiliumNode, error) {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Get(context.TODO(), node, metav1.GetOptions{})
}

func (c *ciliumNodeUpdateImplementation) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if origNode == nil || !origNode.Status.DeepEqual(&node.Status) {
		return ciliumK8sClient.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, metav1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if origNode == nil || !origNode.Spec.DeepEqual(&node.Spec) {
		return ciliumK8sClient.CiliumV2().CiliumNodes().Update(context.TODO(), node, metav1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Delete(nodeName string) error {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Delete(context.TODO(), nodeName, metav1.DeleteOptions{})
}
