//go:build !ignore_autogenerated

/*
Copyright 2024.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureAuth) DeepCopyInto(out *AzureAuth) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureAuth.
func (in *AzureAuth) DeepCopy() *AzureAuth {
	if in == nil {
		return nil
	}
	out := new(AzureAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureValidator) DeepCopyInto(out *AzureValidator) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureValidator.
func (in *AzureValidator) DeepCopy() *AzureValidator {
	if in == nil {
		return nil
	}
	out := new(AzureValidator)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AzureValidator) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureValidatorList) DeepCopyInto(out *AzureValidatorList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AzureValidator, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureValidatorList.
func (in *AzureValidatorList) DeepCopy() *AzureValidatorList {
	if in == nil {
		return nil
	}
	out := new(AzureValidatorList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AzureValidatorList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureValidatorSpec) DeepCopyInto(out *AzureValidatorSpec) {
	*out = *in
	if in.RBACRules != nil {
		in, out := &in.RBACRules, &out.RBACRules
		*out = make([]RBACRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.CommunityGalleryImageRules != nil {
		in, out := &in.CommunityGalleryImageRules, &out.CommunityGalleryImageRules
		*out = make([]CommunityGalleryImageRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.PublicBlobRules != nil {
		in, out := &in.PublicBlobRules, &out.PublicBlobRules
		*out = make([]PublicBlobRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	out.Auth = in.Auth
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureValidatorSpec.
func (in *AzureValidatorSpec) DeepCopy() *AzureValidatorSpec {
	if in == nil {
		return nil
	}
	out := new(AzureValidatorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureValidatorStatus) DeepCopyInto(out *AzureValidatorStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureValidatorStatus.
func (in *AzureValidatorStatus) DeepCopy() *AzureValidatorStatus {
	if in == nil {
		return nil
	}
	out := new(AzureValidatorStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CommunityGallery) DeepCopyInto(out *CommunityGallery) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CommunityGallery.
func (in *CommunityGallery) DeepCopy() *CommunityGallery {
	if in == nil {
		return nil
	}
	out := new(CommunityGallery)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CommunityGalleryImageRule) DeepCopyInto(out *CommunityGalleryImageRule) {
	*out = *in
	out.Gallery = in.Gallery
	if in.Images != nil {
		in, out := &in.Images, &out.Images
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CommunityGalleryImageRule.
func (in *CommunityGalleryImageRule) DeepCopy() *CommunityGalleryImageRule {
	if in == nil {
		return nil
	}
	out := new(CommunityGalleryImageRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PermissionSet) DeepCopyInto(out *PermissionSet) {
	*out = *in
	if in.Actions != nil {
		in, out := &in.Actions, &out.Actions
		*out = make([]ActionStr, len(*in))
		copy(*out, *in)
	}
	if in.DataActions != nil {
		in, out := &in.DataActions, &out.DataActions
		*out = make([]ActionStr, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PermissionSet.
func (in *PermissionSet) DeepCopy() *PermissionSet {
	if in == nil {
		return nil
	}
	out := new(PermissionSet)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PublicBlobRule) DeepCopyInto(out *PublicBlobRule) {
	*out = *in
	if in.Paths != nil {
		in, out := &in.Paths, &out.Paths
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PublicBlobRule.
func (in *PublicBlobRule) DeepCopy() *PublicBlobRule {
	if in == nil {
		return nil
	}
	out := new(PublicBlobRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RBACRule) DeepCopyInto(out *RBACRule) {
	*out = *in
	if in.Permissions != nil {
		in, out := &in.Permissions, &out.Permissions
		*out = make([]PermissionSet, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RBACRule.
func (in *RBACRule) DeepCopy() *RBACRule {
	if in == nil {
		return nil
	}
	out := new(RBACRule)
	in.DeepCopyInto(out)
	return out
}
