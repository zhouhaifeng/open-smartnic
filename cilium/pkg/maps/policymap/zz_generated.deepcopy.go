// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package policymap

import (
	bpf "github.com/cilium/cilium/pkg/bpf"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CallKey) DeepCopyInto(out *CallKey) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CallKey.
func (in *CallKey) DeepCopy() *CallKey {
	if in == nil {
		return nil
	}
	out := new(CallKey)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *CallKey) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CallValue) DeepCopyInto(out *CallValue) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CallValue.
func (in *CallValue) DeepCopy() *CallValue {
	if in == nil {
		return nil
	}
	out := new(CallValue)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *CallValue) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PlumbingKey) DeepCopyInto(out *PlumbingKey) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlumbingKey.
func (in *PlumbingKey) DeepCopy() *PlumbingKey {
	if in == nil {
		return nil
	}
	out := new(PlumbingKey)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *PlumbingKey) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PlumbingValue) DeepCopyInto(out *PlumbingValue) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlumbingValue.
func (in *PlumbingValue) DeepCopy() *PlumbingValue {
	if in == nil {
		return nil
	}
	out := new(PlumbingValue)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *PlumbingValue) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyEntry) DeepCopyInto(out *PolicyEntry) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyEntry.
func (in *PolicyEntry) DeepCopy() *PolicyEntry {
	if in == nil {
		return nil
	}
	out := new(PolicyEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *PolicyEntry) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyKey) DeepCopyInto(out *PolicyKey) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyKey.
func (in *PolicyKey) DeepCopy() *PolicyKey {
	if in == nil {
		return nil
	}
	out := new(PolicyKey)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *PolicyKey) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
